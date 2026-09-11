"""asyncssh wrapper for RouterOS.

Quirks handled here so the rest of the app never sees them:
- username suffix ``+ct``: no colours, no terminal-capability autodetect -> parseable output
- CRLF line endings from RouterOS are normalised to LF
- RouterOS 6 only speaks old KEX/host-key/cipher algorithms and only accepts RSA user keys,
  so the algorithm lists are widened explicitly and two keypairs (ed25519 + RSA) are kept
- host keys are pinned trust-on-first-use into /data/known_hosts; a changed key is an error,
  never silently accepted
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

import asyncssh

from .config import KNOWN_HOSTS_PATH, SSH_COMMAND_TIMEOUT, SSH_CONNECT_TIMEOUT

# Wish-lists; intersected with what this asyncssh build supports (see _algs()).
_KEX = [
    "curve25519-sha256", "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1",
]
_HOSTKEY = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss"]
_CIPHERS = [
    "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com",
    "aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc",
]
_MACS = ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-md5"]
_SIG = ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]


def _algs(wanted: list[str], getter_name: str, module) -> list[str]:
    """Intersect a wish-list with what this asyncssh build supports.

    The getters return bytes, so decode before comparing - a str/bytes mismatch here silently
    yields an empty list and drops us back to asyncssh's defaults, which refuse RouterOS 6.
    """
    try:
        available = {a.decode() if isinstance(a, bytes) else a for a in getattr(module, getter_name)()}
    except Exception:  # pragma: no cover - defensive: fall back to asyncssh defaults
        return []
    return [a for a in wanted if a in available]


def _connect_kwargs() -> dict:
    from asyncssh import encryption, kex, mac, public_key

    kw = {}
    if v := _algs(_KEX, "get_kex_algs", kex):
        kw["kex_algs"] = v
    if v := _algs(_HOSTKEY, "get_public_key_algs", public_key):
        kw["server_host_key_algs"] = v
    if v := _algs(_CIPHERS, "get_encryption_algs", encryption):
        kw["encryption_algs"] = v
    if v := _algs(_MACS, "get_mac_algs", mac):
        kw["mac_algs"] = v
    if v := _algs(_SIG, "get_public_key_algs", public_key):
        kw["signature_algs"] = v
    return kw


class SSHError(Exception):
    """kind: unreachable | timeout | auth_failed | hostkey | error"""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass
class Credentials:
    username: str
    key_pems: list[str] | None = None   # OpenSSH private key texts, tried in order
    password: str | None = None


def _known_hosts_pattern(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def known_host_entry(host: str, port: int) -> str | None:
    if not KNOWN_HOSTS_PATH.exists():
        return None
    pat = _known_hosts_pattern(host, port)
    for line in KNOWN_HOSTS_PATH.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and pat in parts[0].split(","):
            return line
    return None


def forget_host(host: str, port: int) -> None:
    if not KNOWN_HOSTS_PATH.exists():
        return
    pat = _known_hosts_pattern(host, port)
    keep = [l for l in KNOWN_HOSTS_PATH.read_text().splitlines() if not (l.split() and pat in l.split()[0].split(","))]
    KNOWN_HOSTS_PATH.write_text("\n".join(keep) + ("\n" if keep else ""))


async def _pin_host_key(host: str, port: int) -> None:
    """Trust-on-first-use: fetch and store the server key if we have none for this host."""
    if known_host_entry(host, port):
        return
    try:
        kw = _connect_kwargs()
        # get_server_host_key() only takes the negotiation subset, not cipher/mac/signature lists.
        probe_kw = {k: v for k, v in kw.items() if k in ("kex_algs", "server_host_key_algs")}
        key = await asyncio.wait_for(
            asyncssh.get_server_host_key(host, port=port, **probe_kw), SSH_CONNECT_TIMEOUT
        )
    except asyncio.TimeoutError as exc:
        raise SSHError("timeout", f"timeout fetching host key from {host}:{port}") from exc
    except OSError as exc:
        raise SSHError("unreachable", f"{host}:{port}: {exc}") from exc
    if key is None:
        raise SSHError("error", "server returned no host key")
    KNOWN_HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with KNOWN_HOSTS_PATH.open("a") as fh:
        fh.write(f"{_known_hosts_pattern(host, port)} {key.export_public_key('openssh').decode().strip()}\n")


class RouterSSH:
    """``async with RouterSSH(host, port, creds) as r: out = await r.run('/export terse')``"""

    def __init__(self, host: str, port: int, creds: Credentials):
        self.host, self.port, self.creds = host, port, creds
        self._conn: asyncssh.SSHClientConnection | None = None

    async def __aenter__(self) -> "RouterSSH":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def connect(self) -> None:
        await _pin_host_key(self.host, self.port)
        kw = _connect_kwargs()
        client_keys = []
        for pem in self.creds.key_pems or []:
            try:
                client_keys.append(asyncssh.import_private_key(pem))
            except (asyncssh.KeyImportError, ValueError) as exc:
                raise SSHError("error", f"bad private key: {exc}") from exc
        try:
            self._conn = await asyncio.wait_for(
                asyncssh.connect(
                    self.host,
                    port=self.port,
                    username=f"{self.creds.username}+ct",
                    client_keys=client_keys or None,
                    password=self.creds.password,
                    known_hosts=str(KNOWN_HOSTS_PATH),
                    login_timeout=SSH_CONNECT_TIMEOUT,
                    keepalive_interval=15,
                    **kw,
                ),
                SSH_CONNECT_TIMEOUT + 5,
            )
        except asyncio.TimeoutError as exc:
            raise SSHError("timeout", f"connect timeout to {self.host}:{self.port}") from exc
        except asyncssh.PermissionDenied as exc:
            how = "паролем" if self.creds.password else "по ключу"
            hint = ("проверьте пароль от РОУТЕРА (браузер мог подставить пароль от этого интерфейса). "
                    "RouterOS также временно блокирует пользователя после нескольких быстрых неудачных "
                    "попыток — подождите пару минут перед повтором."
                    if self.creds.password else
                    "ключ агента ещё не установлен на устройстве — выполните онбординг или установите ключ вручную.")
            raise SSHError("auth_failed", f"вход {how} для «{self.creds.username}» отклонён: {hint}") from exc
        except asyncssh.HostKeyNotVerifiable as exc:
            raise SSHError("hostkey", f"host key mismatch for {self.host}:{self.port} ({exc}); forget the host key if the router was reinstalled") from exc
        except (asyncssh.KeyExchangeFailed, asyncssh.ProtocolError) as exc:
            raise SSHError("error", f"SSH negotiation failed with {self.host}: {exc}") from exc
        except asyncssh.Error as exc:
            raise SSHError("error", f"{self.host}: {exc}") from exc
        except OSError as exc:
            raise SSHError("unreachable", f"{self.host}:{self.port}: {exc}") from exc

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            try:
                await asyncio.wait_for(self._conn.wait_closed(), 5)
            except Exception:
                pass
            self._conn = None

    async def run(self, command: str, timeout: int = SSH_COMMAND_TIMEOUT) -> str:
        assert self._conn is not None, "not connected"
        try:
            result = await asyncio.wait_for(self._conn.run(command, check=False, term_type=None), timeout)
        except asyncio.TimeoutError as exc:
            raise SSHError("timeout", f"command timed out after {timeout}s: {redact(command)[:120]}") from exc
        except asyncssh.Error as exc:
            raise SSHError("error", f"command failed: {exc}") from exc
        out = (result.stdout or "") + (result.stderr or "")
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return normalize(out)

    async def upload_text(self, remote_name: str, content: str) -> None:
        """Write a small text file on the router. SFTP needs the 'ftp' policy on the user."""
        assert self._conn is not None, "not connected"
        try:
            async with self._conn.start_sftp_client() as sftp:
                async with sftp.open(remote_name, "w") as fh:
                    await fh.write(content)
        except (asyncssh.Error, OSError) as exc:
            raise SSHError("error", f"sftp upload failed: {exc}") from exc


_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def redact(command: str) -> str:
    """Strip secrets from a command before it can reach an error message, log or the audit table.

    Onboarding sends ``/user add ... password="..."``; embedding the raw command in a timeout
    error put that credential into stored audit rows.
    """
    from .scrub import scrub

    return scrub(command)[0]


def normalize(text: str) -> str:
    text = _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return text.strip("\n")


def parse_print(text: str) -> dict[str, str]:
    """``key: value`` lines of a ``print`` without ``terse`` -> dict (e.g. /system resource print)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            if k and " " not in k:
                out[k] = v.strip()
    return out


def parse_print_terse(text: str) -> list[dict[str, str]]:
    """``print terse`` output -> list of records; flags kept under ``_flags``, index under ``_id``."""
    rows = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+([A-Z ]*?)\s*((?:[\w.-]+=.*)?)$", line)
        if not m:
            continue
        rec = {"_id": m.group(1), "_flags": m.group(2).strip()}
        for k, v in re.findall(r'([\w.-]+)=("(?:[^"\\]|\\.)*"|\S*)', m.group(3)):
            rec[k] = v.strip('"')
        rows.append(rec)
    return rows


def generate_keypair(kind: str) -> tuple[str, str]:
    """Return (private_openssh_pem, public_openssh_line) for 'ed25519' or 'rsa'."""
    if kind == "rsa":
        key = asyncssh.generate_private_key("ssh-rsa", key_size=4096, comment="mikrotik-agent")
    else:
        key = asyncssh.generate_private_key("ssh-ed25519", comment="mikrotik-agent")
    return key.export_private_key("openssh").decode(), key.export_public_key("openssh").decode().strip()
