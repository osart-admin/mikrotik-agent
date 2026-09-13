"""One-time per-device setup: create a read-only user with our public key.

Runs with admin credentials supplied in the request only - they are never stored. This is the
single write operation in phase 1 and is always user-triggered from the device page.
"""
from __future__ import annotations

import secrets as pysecrets
import sqlite3

from . import collector, db
from .ssh import Credentials, RouterSSH, SSHError, parse_print, parse_print_terse

GROUP = "mikrotik-agent-ro"
# Only positive policies: unlisted ones are disabled. Deliberately minimal - the collector runs
# exactly four commands (/system resource|identity|routerboard print and /export), all covered by
# 'read'. In particular:
#   'write'     - the read path must be incapable of changing anything
#   'sensitive' - makes the router itself refuse to hand over secrets, before the scrubber
#   'test'      - grants bandwidth-test and flood-ping, i.e. the ability to saturate a link.
#                 Add it only when live diagnostics (ping/traceroute) are actually implemented.
GROUP_POLICY = "ssh,read"

# Write path (phase 4). Deliberately no 'policy': that would grant user management. The rollback
# scheduler is therefore created once here, by the admin, and the write account only toggles it.
WRITE_GROUP = "mikrotik-agent-rw"
WRITE_GROUP_POLICY = "ssh,read,write"

# Every policy RouterOS knows, so a group can be pinned to exactly what we intend.
ALL_POLICIES = ("local", "telnet", "ssh", "ftp", "reboot", "read", "write", "policy", "test",
                "winbox", "password", "web", "sniff", "sensitive", "api", "romon", "rest-api")


def exact_policy(granted: str) -> str:
    """Turn "ssh,read" into "ssh,read,!local,!telnet,..." - every other policy explicitly denied.

    `/user group add policy=...` denies unlisted policies, but `/user group set policy=...` does
    NOT: on RouterOS 7.22 a set with only positive entries leaves previously granted policies in
    place. Verified on hardware - a group that already had wider rights silently kept them, so
    "existing group, policy reset" was a lie. Always send the negations.
    """
    keep = [p.strip() for p in granted.split(",") if p.strip()]
    unknown = [p for p in keep if p not in ALL_POLICIES]
    if unknown:
        raise ValueError(f"unknown RouterOS policy: {', '.join(unknown)}")
    return ",".join(keep + [f"!{p}" for p in ALL_POLICIES if p not in keep])


def key_kind_for(version: str) -> str:
    """Which agent key a router can take as a *user* key.

    RouterOS only accepts ed25519 user keys from 7.12. Earlier 7.x accepts the import command
    silently and stores nothing (seen on 7.6: `/user ssh-keys print` stays empty), so the key
    login fails right after a "successful" onboarding. Unknown versions get ed25519.
    """
    parts = (version or "").split(" ")[0].split(".")
    try:
        major = int(parts[0])
        minor = int("".join(ch for ch in parts[1] if ch.isdigit()) or 0) if len(parts) > 1 else 0
    except ValueError:
        return "ed25519"
    return "ed25519" if (major, minor) >= (7, 12) else "rsa"


def manual_script(agent_user: str, pubkey: str, key_kind: str, allowed_address: str = "") -> str:
    """The same steps onboard() performs, as commands to paste into the router's terminal.

    Offered because the automated path needs the router's admin password, which the operator may
    not want to type into a web form - and which browsers like to autofill wrongly.
    """
    addr = f" address={allowed_address}" if allowed_address else ""
    fname = f"{agent_user}-{key_kind}.pub"
    return "\n".join([
        f"/user group add name={GROUP} policy={exact_policy(GROUP_POLICY)}",
        f'/user add name={agent_user} group={GROUP}{addr} password="{pysecrets.token_urlsafe(24)}"',
        f'/file add name="{fname}" contents="{pubkey}"',
        f"/user ssh-keys import user={agent_user} public-key-file={fname}",
        f'/file remove [ find name="{fname}" ]',
    ])


async def _assert_group_policy(r: RouterSSH, group: str, expected: str) -> None:
    """Read the group back and fail loudly if it is wider than intended.

    Silently keeping extra rights is the failure mode this guards against; the operator must not
    be told a group is read-only when it is not.
    """
    rows = parse_print_terse(await r.run(f'/user group print terse where name="{group}"'))
    if not rows:
        raise SSHError("error", f"группа {group} не найдена после настройки")
    actual = {p for p in rows[0].get("policy", "").split(",") if p and not p.startswith("!")}
    want = {p.strip() for p in expected.split(",") if p.strip()}
    if actual != want:
        extra = ", ".join(sorted(actual - want)) or "—"
        raise SSHError("error",
                       f"группа {group} получила не те политики: лишние [{extra}], "
                       f"ожидалось [{expected}]. Исправьте вручную на устройстве.")


async def _put_file(r: RouterSSH, name: str, content: str, major: int) -> None:
    try:
        await r.upload_text(name, content)
        return
    except SSHError:
        pass
    if major >= 7:
        out = await r.run(f'/file add name="{name}" contents="{content}"')
        if "error" in out.lower() or "failure" in out.lower():
            raise SSHError("error", f"/file add failed: {out[:200]}")
    else:
        base = name.rsplit(".", 1)[0]
        await r.run(f"/file print file={base}")
        out = await r.run(f'/file set {base}.txt contents="{content}"')
        if "error" in out.lower() or "failure" in out.lower():
            raise SSHError("error", f"/file set failed: {out[:200]}")


async def onboard(dev: sqlite3.Row, admin_user: str, admin_password: str, agent_user: str, allowed_address: str = "") -> list[str]:
    log: list[str] = []
    pubs = collector.public_keys()
    async with RouterSSH(dev["host"], dev["port"], Credentials(admin_user, password=admin_password)) as r:
        res = parse_print(await r.run("/system resource print"))
        version = (res.get("version") or "?").split(" ")[0]
        major = int(version.split(".")[0]) if version[:1].isdigit() else 7
        log.append(f"connected as {admin_user}: RouterOS {version}")
        key_kind = key_kind_for(version)
        pub = pubs[key_kind]
        if not pub:
            raise SSHError("error", "no public key generated yet")

        groups = {g.get("name") for g in parse_print_terse(await r.run("/user group print terse"))}
        if GROUP in groups:
            await r.run(f'/user group set [ find name="{GROUP}" ] policy={exact_policy(GROUP_POLICY)}')
            log.append(f"group {GROUP} exists, policy reset to {GROUP_POLICY}")
        else:
            out = await r.run(f"/user group add name={GROUP} policy={exact_policy(GROUP_POLICY)}")
            if out.strip():
                raise SSHError("error", f"group add failed: {out[:200]}")
            log.append(f"group {GROUP} created with policy {GROUP_POLICY}")
        await _assert_group_policy(r, GROUP, GROUP_POLICY)

        users = {u.get("name") for u in parse_print_terse(await r.run("/user print terse"))}
        addr = f" address={allowed_address}" if allowed_address else ""
        if agent_user in users:
            out = await r.run(f'/user set [ find name="{agent_user}" ] group={GROUP}{addr}')
            log.append(f"user {agent_user} exists, moved to group {GROUP}")
        else:
            pw = pysecrets.token_urlsafe(24)
            out = await r.run(f'/user add name={agent_user} group={GROUP} password="{pw}"{addr}')
            log.append(f"user {agent_user} created (random password, key auth only)")
        if out.strip() and "error" in out.lower():
            raise SSHError("error", f"user setup failed: {out[:200]}")

        fname = f"{agent_user}-{key_kind}.pub"
        await _put_file(r, fname, pub, major)
        out = await r.run(f"/user ssh-keys import user={agent_user} public-key-file={fname}")
        if out.strip() and "already" not in out.lower():
            raise SSHError("error", f"ssh-keys import failed: {out[:200]}")
        log.append(f"{key_kind} public key imported for {agent_user}")
        await r.run(f'/file remove [ find name="{fname}" ]')

    # Verify with the new identity before switching the device over.
    creds = Credentials(agent_user, key_pems=[db.get_secret(collector.KEY_RSA if key_kind == "rsa" else collector.KEY_ED25519) or ""])
    async with RouterSSH(dev["host"], dev["port"], creds) as r:
        ident = parse_print(await r.run("/system identity print")).get("name", "")
    log.append(f"verified key login as {agent_user} (identity {ident})")
    db.update_device(dev["id"], {"username": agent_user, "auth": "key", "password_enc": None, "ros_version": version, "status": "ok", "status_message": "onboarded"})
    log.append("device switched to key auth")
    return log


async def onboard_write(dev: sqlite3.Row, admin_user: str, admin_password: str,
                        write_user: str = "agent-rw", allowed_address: str = "") -> list[str]:
    """Provision the write account and the pre-installed rollback scheduler.

    Separate from read onboarding and never implied by it: a device becomes changeable only when
    the operator asks for it explicitly, per device.
    """
    from .apply import BACKUP_NAME, SCHEDULER_NAME

    log: list[str] = []
    pubs = collector.public_keys()
    async with RouterSSH(dev["host"], dev["port"], Credentials(admin_user, password=admin_password)) as r:
        res = parse_print(await r.run("/system resource print"))
        version = (res.get("version") or "?").split(" ")[0]
        major = int(version.split(".")[0]) if version[:1].isdigit() else 7
        key_kind = key_kind_for(version)
        pub = pubs[key_kind]
        if not pub:
            raise SSHError("error", "no public key generated yet")
        log.append(f"подключились как {admin_user}: RouterOS {version}")

        groups = {g.get("name") for g in parse_print_terse(await r.run("/user group print terse"))}
        if WRITE_GROUP in groups:
            await r.run(f'/user group set [ find name="{WRITE_GROUP}" ] policy={exact_policy(WRITE_GROUP_POLICY)}')
            log.append(f"группа {WRITE_GROUP} уже была, политики приведены к {WRITE_GROUP_POLICY}")
        else:
            out = await r.run(f"/user group add name={WRITE_GROUP} policy={exact_policy(WRITE_GROUP_POLICY)}")
            if out.strip():
                raise SSHError("error", f"не удалось создать группу: {out[:200]}")
            log.append(f"создана группа {WRITE_GROUP}: {WRITE_GROUP_POLICY} — без policy и sensitive")
        await _assert_group_policy(r, WRITE_GROUP, WRITE_GROUP_POLICY)

        users = {u.get("name") for u in parse_print_terse(await r.run("/user print terse"))}
        addr = f" address={allowed_address}" if allowed_address else ""
        if write_user in users:
            await r.run(f'/user set [ find name="{write_user}" ] group={WRITE_GROUP}{addr}')
            log.append(f"пользователь {write_user} уже был, переведён в {WRITE_GROUP}")
        else:
            pw = pysecrets.token_urlsafe(24)
            out = await r.run(f'/user add name={write_user} group={WRITE_GROUP} password="{pw}"{addr}')
            if out.strip() and "error" in out.lower():
                raise SSHError("error", f"не удалось создать пользователя: {out[:200]}")
            log.append(f"создан пользователь {write_user} (вход только по ключу)")

        fname = f"{write_user}-{key_kind}.pub"
        await _put_file(r, fname, pub, major)
        out = await r.run(f"/user ssh-keys import user={write_user} public-key-file={fname}")
        if out.strip() and "already" not in out.lower():
            raise SSHError("error", f"не удалось импортировать ключ: {out[:200]}")
        await r.run(f'/file remove [ find name="{fname}" ]')
        log.append(f"ключ {key_kind} импортирован для {write_user}")

        # Created here, by admin, because a scheduler carrying commands needs the 'policy' right.
        # Left disabled; the write account only ever flips disabled/interval, never the script.
        await r.run(f'/system scheduler remove [find name="{SCHEDULER_NAME}"]')
        out = await r.run(
            f'/system scheduler add name="{SCHEDULER_NAME}" start-time=startup interval=10m '
            f'disabled=yes on-event="/system backup load name={BACKUP_NAME} password=\\"\\""'
        )
        if out.strip():
            raise SSHError("error", f"не удалось поставить задачу отката: {out[:200]}")
        log.append(f"установлена задача отката {SCHEDULER_NAME} — выключена, восстанавливает {BACKUP_NAME}")

    key_secret = collector.KEY_RSA if key_kind == "rsa" else collector.KEY_ED25519
    creds = Credentials(write_user, key_pems=[db.get_secret(key_secret) or ""])
    async with RouterSSH(dev["host"], dev["port"], creds) as r:
        probe = await r.run("/system note set show-at-login=no")
        if "not enough permissions" in probe.lower():
            raise SSHError("error", f"{write_user} не может писать — проверьте группу {WRITE_GROUP}")
        armed = await r.run(f'/system scheduler print count-only where name="{SCHEDULER_NAME}"')
        if armed.strip() in ("0", ""):
            raise SSHError("error", "задача отката не найдена после установки")
    log.append(f"проверено: {write_user} входит по ключу, может писать, задача отката на месте")

    db.set_setting("write_user", write_user)
    db.update_device(dev["id"], {"write_enabled": 1})
    log.append("путь записи на устройстве включён")
    return log
