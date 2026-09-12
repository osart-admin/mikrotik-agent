"""Applying an approved change plan, with a rollback that survives losing the connection.

**DORMANT.** Automatic applying is disabled (`apply_enabled` setting, default off) because the
rollback safety net cannot be built with a minimal write account on RouterOS 7.22:

* a `/system scheduler` entry carries the policy set of whoever created it, and editing one
  requires holding *all* of those policies - so the agent cannot even toggle `disabled`, with or
  without the `policy` right;
* `/system backup save` is refused for `ssh,read,write`, `+ftp` and `+policy`, and only succeeds
  with a near-full policy set.

Granting the write account what it would need defeats the separation the design exists for, so
plans are prepared and validated here and executed by a human in Winbox instead. The code below
is kept intact: it becomes usable again if a scheduler created with an explicit narrow `policy=`
turns out to be editable by an account holding that same narrow set - the experiment that was not
run. See docs/DECISIONS.md.

Original design follows.

The dangerous failure mode is not a bad command - the validator handles that - it is a *good*
command that cuts the agent off from the device: a firewall rule, an address change, a disabled
interface. The operator then has no way back in.

So applying uses commit/confirm, driven from the router itself:

1. save the backup under a **fixed** name (`agent-rollback`), overwriting the previous one;
2. enable the pre-installed rollback scheduler with an interval of N minutes;
3. apply the change;
4. the operator confirms in the UI that the device is still reachable, which disables the
   scheduler again.

If step 3 or 4 loses connectivity, nobody has to do anything: the router restores itself.

**Why the scheduler is pre-installed rather than created per apply.** RouterOS requires the
`policy` permission to create a scheduler entry that carries commands - and `policy` also grants
user management, which would make the write account nearly omnipotent. So the entry is created
once, disabled, during write-onboarding by a human using admin credentials, with a fixed
on-event. From then on the agent only toggles `disabled` and `interval`, which `write` covers,
and the script it runs can never be changed by a plan.

That is also why `/system scheduler`, `/system backup load` and `/file` are on the validator's
forbidden list: the rollback machinery owns them, and a plan must not be able to disarm its own
safety net.

The write session uses a separate router account from the collector, so the read path keeps no
write rights - see onboard.py.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from . import collector, db
from .ssh import Credentials, RouterSSH, SSHError, redact

log = logging.getLogger("apply")

SCHEDULER_NAME = "mikrotik-agent-rollback"
BACKUP_NAME = "agent-rollback"      # fixed, so the scheduler's on-event never has to change
DEFAULT_ROLLBACK_MINUTES = 10
MIN_ROLLBACK_MINUTES = 2
MAX_ROLLBACK_MINUTES = 60
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


class ApplyError(Exception):
    pass


def write_credentials(dev: dict[str, Any]) -> Credentials:
    """Credentials for the write-capable account, which is deliberately not the collector's."""
    user = (db.get_setting("write_user", "") or "agent-rw").strip()
    keys = [db.get_secret(collector.KEY_ED25519) or "", db.get_secret(collector.KEY_RSA) or ""]
    if (dev.get("ros_version") or "").startswith("6"):
        keys.reverse()
    return Credentials(user, key_pems=[k for k in keys if k])


def _check(out: str, what: str) -> None:
    low = out.lower()
    if "not enough permissions" in low:
        raise ApplyError(
            f"{what}: у пользователя записи нет прав. Выполните онбординг записи на этом устройстве."
        )
    for marker in ("failure:", "syntax error", "bad command name", "no such item", "expected end of command",
                   "input does not match", "invalid value"):
        if marker in low:
            raise ApplyError(f"{what}: {out.strip()[:200]}")


async def preflight(dev: dict[str, Any]) -> dict[str, str]:
    """Confirm the write account exists and can actually write, before touching anything."""
    async with RouterSSH(dev["host"], dev["port"], write_credentials(dev)) as r:
        ident = (await r.run("/system identity print")).strip()
        probe = await r.run("/system note set show-at-login=no")
        _check(probe, "проверка прав записи")
    return {"identity": ident, "ok": "yes"}


async def apply_plan(plan: dict[str, Any], rollback_minutes: int, confirmer: str) -> dict[str, Any]:
    """Back up, arm the rollback, apply. Returns state for the operator to confirm."""
    dev = db.get_device(plan["device_id"])
    if dev is None:
        raise ApplyError("устройство удалено")
    dev = dict(dev)

    rollback_minutes = max(MIN_ROLLBACK_MINUTES, min(int(rollback_minutes), MAX_ROLLBACK_MINUTES))
    backup = BACKUP_NAME

    commands = [c for c in plan["commands"].splitlines() if c.strip() and not c.strip().startswith("#")]
    if not commands:
        raise ApplyError("план пуст")

    transcript: list[str] = []
    # Tracked so a failure can say truthfully how far it got. Offering "restore the backup" when
    # the backup step itself failed would restore a file that does not exist, or a stale one.
    backup_ok = False
    armed_ok = False
    changed = False

    def _fail(message: str, kind: str) -> None:
        db.update_plan(plan["id"], {
            "status": "failed", "error": message, "output": "\n\n".join(transcript),
            # Only claim a backup when one was actually written.
            "backup_name": backup if backup_ok else "",
        })
        log.warning("plan #%s failed on %s (%s): %s", plan["id"], dev["slug"], kind, message)

    try:
        async with RouterSSH(dev["host"], dev["port"], write_credentials(dev)) as r:
            # Everything that can fail without touching the configuration is checked first, so a
            # misconfigured device leaves the plan exactly as it was.
            armed = await r.run(f'/system scheduler print count-only where name="{SCHEDULER_NAME}"')
            if "not enough permissions" in armed.lower():
                raise ApplyError(
                    "пользователь записи не видит задачу отката — проверьте его группу. "
                    "Ничего не изменено."
                )
            if armed.strip() in ("0", ""):
                raise ApplyError(
                    "на устройстве нет задачи отката — выполните онбординг записи. "
                    "Без неё применять изменения небезопасно. Ничего не изменено."
                )

            out = await r.run(f"/system backup save name={backup} dont-encrypt=yes", timeout=120)
            _check(out, "создание бэкапа")
            backup_ok = True
            transcript.append(f"$ /system backup save name={backup}\n{out.strip()}")

            # Armed BEFORE the change, so a command that cuts us off is still recovered from.
            # Only disabled/interval are touched: changing on-event would need the policy right.
            out = await r.run(f'/system scheduler set [find name="{SCHEDULER_NAME}"] '
                              f'interval={rollback_minutes}m disabled=no')
            _check(out, "постановка отката")
            armed_ok = True
            transcript.append(f"$ откат через {rollback_minutes} мин вооружён")

            for cmd in commands:
                out = await r.run(cmd, timeout=60)
                changed = True
                transcript.append(f"$ {redact(cmd)}\n{out.strip()}")
                _check(out, f"команда «{redact(cmd)[:60]}»")
    except SSHError as exc:
        _fail(f"{exc.kind}: {exc.message}", "ssh")
        if armed_ok:
            raise ApplyError(
                f"связь с устройством потеряна ({exc.kind}). Откат вооружён — роутер "
                f"восстановится сам через {rollback_minutes} мин, вмешиваться не нужно."
            ) from exc
        raise ApplyError(
            f"связь с устройством потеряна ({exc.kind}) до применения изменений. "
            f"Конфигурация не тронута."
        ) from exc
    except ApplyError as exc:
        _fail(str(exc), "apply")
        if armed_ok and changed:
            raise ApplyError(
                f"{exc} Часть команд уже выполнена, откат вооружён на {rollback_minutes} мин — "
                f"либо откатите сейчас, либо дождитесь автоматического отката."
            ) from exc
        if armed_ok:
            # Nothing was changed, so leave the device clean rather than waiting for a reboot.
            try:
                async with RouterSSH(dev["host"], dev["port"], write_credentials(dev)) as r2:
                    await r2.run(f'/system scheduler set [find name="{SCHEDULER_NAME}"] disabled=yes')
            except SSHError:
                log.warning("plan #%s: could not disarm rollback after a no-op failure", plan["id"])
        raise

    deadline = (datetime.now(timezone.utc) + timedelta(minutes=rollback_minutes)).replace(microsecond=0)
    db.update_plan(plan["id"], {
        "status": "awaiting_confirm", "applied_at": db.now_iso(), "backup_name": backup,
        "rollback_deadline": deadline.isoformat(), "output": "\n\n".join(transcript),
        "approved_by": confirmer, "error": "",
    })
    log.info("plan #%s applied to %s, rollback armed for %s", plan["id"], dev["slug"], deadline)
    return {"backup": backup, "rollback_deadline": deadline.isoformat(), "minutes": rollback_minutes,
            "transcript": "\n\n".join(transcript)}


async def confirm_plan(plan: dict[str, Any], confirmer: str) -> None:
    """Operator says the device is fine: disarm the rollback and keep the change."""
    dev = dict(db.get_device(plan["device_id"]) or {})
    if not dev:
        raise ApplyError("устройство удалено")
    async with RouterSSH(dev["host"], dev["port"], write_credentials(dev)) as r:
        out = await r.run(f'/system scheduler set [find name="{SCHEDULER_NAME}"] disabled=yes')
        _check(out, "снятие отката")
        still_armed = await r.run(
            f'/system scheduler print count-only where name="{SCHEDULER_NAME}" and !disabled')
        if still_armed.strip() not in ("0", ""):
            raise ApplyError("не удалось снять задачу отката — проверьте устройство вручную")
    db.update_plan(plan["id"], {"status": "applied", "confirmed_at": db.now_iso(),
                                "approved_by": confirmer, "rollback_deadline": None})
    log.info("plan #%s confirmed on %s", plan["id"], dev.get("slug"))


async def rollback_now(plan: dict[str, Any], actor: str) -> None:
    """Operator aborts: restore the backup immediately. The device reboots as part of this."""
    dev = dict(db.get_device(plan["device_id"]) or {})
    if not dev:
        raise ApplyError("устройство удалено")
    backup = plan.get("backup_name") or BACKUP_NAME
    if not _SAFE_NAME.match(backup):
        raise ApplyError("нет корректного имени бэкапа для отката")
    try:
        async with RouterSSH(dev["host"], dev["port"], write_credentials(dev)) as r:
            await r.run(f'/system backup load name={backup} password=""', timeout=20)
    except SSHError:
        # Expected: restoring a backup reboots the device, so the session dies mid-command.
        pass
    db.update_plan(plan["id"], {"status": "rolled_back", "confirmed_at": db.now_iso(),
                                "approved_by": actor, "rollback_deadline": None})
    log.info("plan #%s rolled back on %s", plan["id"], dev.get("slug"))
