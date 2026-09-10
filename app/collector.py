"""Collection run: SSH into every enabled device, store the export, commit once.

Volatile values (uptime, cpu) go to SQLite only; git sees the header-less export and facts.
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from typing import Any

from . import db, facts, rsc, store
from .config import COLLECT_CONCURRENCY
from .ssh import Credentials, RouterSSH, SSHError, generate_keypair, parse_print

log = logging.getLogger("collector")
_run_lock = asyncio.Lock()

KEY_ED25519 = "ssh_key_ed25519"
KEY_RSA = "ssh_key_rsa"


def ensure_keys() -> None:
    for name, kind in ((KEY_ED25519, "ed25519"), (KEY_RSA, "rsa")):
        if not db.has_secret(name):
            priv, pub = generate_keypair(kind)
            db.set_secret(name, priv)
            db.set_setting(name + "_pub", pub)
            log.info("generated %s keypair", kind)


def public_keys() -> dict[str, str]:
    return {"ed25519": db.get_setting(KEY_ED25519 + "_pub", "") or "", "rsa": db.get_setting(KEY_RSA + "_pub", "") or ""}


def credentials_for(dev: sqlite3.Row | dict) -> Credentials:
    if dev["auth"] == "password":
        return Credentials(dev["username"], password=db.device_password(dev))
    keys = [db.get_secret(KEY_ED25519) or "", db.get_secret(KEY_RSA) or ""]
    if (dev["ros_version"] or "").startswith("6"):
        keys.reverse()  # RouterOS 6 only understands RSA user keys; try it first
    return Credentials(dev["username"], key_pems=[k for k in keys if k])


def _version(res: dict[str, str]) -> str:
    return (res.get("version") or "").split(" ")[0]


async def probe(dev: sqlite3.Row | dict) -> dict[str, str]:
    """Connect and read identity/version - the 'Test connection' button."""
    async with RouterSSH(dev["host"], dev["port"], credentials_for(dev)) as r:
        res = parse_print(await r.run("/system resource print"))
        ident = parse_print(await r.run("/system identity print")).get("name", "")
    return {"identity": ident, "version": _version(res), "board": res.get("board-name", ""), "arch": res.get("architecture-name", "")}


async def collect_device(dev: sqlite3.Row, run_id: int) -> tuple[str, str, bool]:
    """Return (status, message, changed) and persist everything about this device."""
    t0 = time.monotonic()
    try:
        async with RouterSSH(dev["host"], dev["port"], credentials_for(dev)) as r:
            res = parse_print(await r.run("/system resource print"))
            ident = parse_print(await r.run("/system identity print")).get("name", "")
            rb = parse_print(await r.run("/system routerboard print"))
            export = await r.run("/export terse hide-sensitive")
        body = rsc.strip_header(export)
        if not body.startswith("/"):
            raise SSHError("error", "unexpected export output: " + body[:120].replace("\n", " | "))
        fx = facts.extract(body)
        changed = store.write_device(dev["slug"], body, facts.to_json(fx))
        now = db.now_iso()
        fields: dict[str, Any] = {
            "status": "ok", "status_message": "", "identity": ident or fx.get("identity") or dev["identity"],
            "ros_version": _version(res) or dev["ros_version"], "board": res.get("board-name") or dev["board"],
            "model": rb.get("model") or res.get("board-name") or dev["model"],
            "serial": rb.get("serial-number") or dev["serial"], "arch": res.get("architecture-name") or dev["arch"],
            "uptime": res.get("uptime", ""), "cpu_load": res.get("cpu-load", ""),
            "last_seen": now, "last_collected": now, "export_lines": len(body.splitlines()),
        }
        if changed:
            fields["last_changed"] = now
        db.update_device(dev["id"], fields)
        status, message = "ok", ""
    except SSHError as exc:
        status, message, changed = exc.kind, exc.message, False
        db.update_device(dev["id"], {"status": status, "status_message": message})
        log.warning("%s: %s: %s", dev["slug"], status, message)
    except Exception as exc:  # noqa: BLE001 - one device must never take the run down
        status, message, changed = "error", f"{type(exc).__name__}: {exc}", False
        db.update_device(dev["id"], {"status": status, "status_message": message})
        log.exception("%s: unexpected failure", dev["slug"])
    db.record_run_device(run_id, dev["id"], status, message, changed, int((time.monotonic() - t0) * 1000))
    return status, message, changed


def is_running() -> bool:
    return _run_lock.locked()


async def collect_all(trigger: str = "manual", device_ids: list[int] | None = None) -> dict[str, Any]:
    if _run_lock.locked():
        return {"skipped": True, "reason": "a collection run is already in progress"}
    async with _run_lock:
        store.ensure_repo()
        run_id = db.start_run(trigger)
        devices = [d for d in db.list_devices(enabled_only=True) if not device_ids or d["id"] in device_ids]
        sem = asyncio.Semaphore(COLLECT_CONCURRENCY)

        async def one(dev: sqlite3.Row) -> tuple[str, str, bool]:
            async with sem:
                return await collect_device(dev, run_id)

        results = await asyncio.gather(*(one(d) for d in devices))
        ok = sum(1 for s, _, _ in results if s == "ok")
        changed_slugs = [d["slug"] for d, (s, _, c) in zip(devices, results) if s == "ok" and c]
        sha = None
        if changed_slugs:
            sha = store.commit(f"run #{run_id} ({trigger}): {len(changed_slugs)} changed: {', '.join(changed_slugs)}")
        db.finish_run(run_id, ok, len(devices) - ok, len(changed_slugs), sha)
        log.info("run #%d done: %d ok, %d failed, %d changed", run_id, ok, len(devices) - ok, len(changed_slugs))
        return {"run_id": run_id, "ok": ok, "failed": len(devices) - ok, "changed": changed_slugs, "commit": sha}
