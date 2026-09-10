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
# Only positive policies: unlisted ones are disabled, and crucially 'sensitive' and 'write' stay off.
GROUP_POLICY = "ssh,read,test"


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
        key_kind = "rsa" if major < 7 else "ed25519"
        pub = pubs[key_kind]
        if not pub:
            raise SSHError("error", "no public key generated yet")

        groups = {g.get("name") for g in parse_print_terse(await r.run("/user group print terse"))}
        if GROUP in groups:
            await r.run(f'/user group set [ find name="{GROUP}" ] policy={GROUP_POLICY}')
            log.append(f"group {GROUP} exists, policy reset to {GROUP_POLICY}")
        else:
            out = await r.run(f"/user group add name={GROUP} policy={GROUP_POLICY}")
            if out.strip():
                raise SSHError("error", f"group add failed: {out[:200]}")
            log.append(f"group {GROUP} created with policy {GROUP_POLICY}")

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
