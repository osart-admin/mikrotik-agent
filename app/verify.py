"""Check a plan marked as done against the configuration collected afterwards.

"Done" means the operator pasted the commands, not that each one changed something. A
`[find where ... comment=""]` that matches nothing, or a line lost from the paste, leaves the
router as it was and no error reaches this app. Each command is compared with the exports taken
before and after, so the plan page can name the lines that left no trace.

Only what an export can show is judged: a value RouterOS omits because it is the default, or a
selector this module does not understand, is reported as unchecked rather than guessed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from . import rsc, store

# Arguments that say where or whether, not what: an export never repeats them as written.
_POSITIONAL = frozenset({"place-before"})
_COND = re.compile(r'([\w.-]+)=("(?:[^"\\]|\\.)*"|\S*)|(\S+)')


@dataclass
class LineCheck:
    line: int
    command: str
    status: str      # ok | missing | unknown
    note: str


def _unquote(v: str) -> str:
    return v[1:-1].replace('\\"', '"').replace("\\\\", "\\") if len(v) >= 2 and v[0] == v[-1] == '"' else v


def conditions(selector: str) -> dict[str, str] | None:
    """`find where a=b and c="d"` -> {a: b, c: d}; None for anything but plain equality."""
    s = selector.strip()
    if not s.startswith("find"):
        return None
    body = s[4:].strip()
    if body.startswith("where"):
        body = body[5:].strip()
    out: dict[str, str] = {}
    for key, value, bare in _COND.findall(body):
        if bare:
            if bare == "and":
                continue
            return None          # or, !, ~, ranges: not evaluated
        out[key] = _unquote(value)
    return out


def _attrs(e: rsc.Entry) -> dict[str, str]:
    attrs = dict(conditions(e.selector) or {})
    attrs.update(e.args)
    attrs.setdefault("disabled", "no")
    return attrs


def _matches(e: rsc.Entry, conds: dict[str, str]) -> bool:
    attrs = _attrs(e)
    return all(attrs.get(k, "") == v for k, v in conds.items())


def _identity(e: rsc.Entry) -> tuple[str, frozenset[tuple[str, str]]]:
    return e.path, frozenset((k, v) for k, v in _attrs(e).items() if k != "disabled")


def _wanted(args: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in args.items() if k not in _POSITIONAL and not (k == "disabled" and v == "no")}


def check(commands: list[str], before: str, after: str) -> list[LineCheck]:
    old = [e for e in rsc.parse(before) if e.verb in ("add", "set")]
    new = [e for e in rsc.parse(after) if e.verb in ("add", "set")]
    out: list[LineCheck] = []
    for i, cmd in enumerate(commands, 1):
        parsed = rsc.parse(cmd)
        if not parsed:
            out.append(LineCheck(i, cmd, "unknown", "команда не разобрана"))
            continue
        out.append(_check_one(i, cmd, parsed[0], old, new))
    return out


def _check_one(i: int, cmd: str, p: rsc.Entry, old: list[rsc.Entry], new: list[rsc.Entry]) -> LineCheck:
    want = _wanted(p.args)

    if p.verb == "add":
        def count(entries: list[rsc.Entry]) -> int:
            return sum(1 for e in entries if e.path == p.path and e.verb == "add"
                       and all(_attrs(e).get(k) == v for k, v in want.items()))
        if count(new) > count(old):
            return LineCheck(i, cmd, "ok", "запись появилась")
        return LineCheck(i, cmd, "missing", "такой записи в конфигурации нет")

    if p.verb == "set" and not p.selector:
        merged: dict[str, str] = {}
        for e in new:
            if e.path == p.path and not e.selector:
                merged.update(e.args)
        wrong = {k: v for k, v in want.items() if k in merged and merged[k] != v}
        if wrong:
            k = next(iter(wrong))
            return LineCheck(i, cmd, "missing", f"{k}={merged[k]}, а не {want[k]}")
        if all(k in merged for k in want):
            return LineCheck(i, cmd, "ok", "значения выставлены")
        return LineCheck(i, cmd, "unknown", "значение по умолчанию экспорт не показывает")

    if p.verb not in ("set", "disable", "enable", "remove"):
        return LineCheck(i, cmd, "unknown", "не проверяется")
    conds = conditions(p.selector)
    if conds is None:
        return LineCheck(i, cmd, "unknown", "условие выбора записей не проверяется")
    targets = [e for e in old if e.path == p.path and _matches(e, conds)]
    if not targets:
        return LineCheck(i, cmd, "unknown", "до выполнения под условие не попадала ни одна запись")

    after_by_id: dict[Any, list[rsc.Entry]] = {}
    for e in new:
        if e.path == p.path:
            after_by_id.setdefault(_identity(e), []).append(e)

    failed = 0
    for t in targets:
        if p.verb == "remove":
            failed += bool(after_by_id.get(_identity(t)))
            continue
        if p.verb == "set":
            updated = rsc.Entry(t.path, t.verb, {**t.args, **p.args}, t.selector)
            failed += not after_by_id.get(_identity(updated))
            continue
        want_disabled = "yes" if p.verb == "disable" else "no"
        same = after_by_id.get(_identity(t), [])
        failed += not any(_attrs(e)["disabled"] == want_disabled for e in same)

    what = {"disable": "остались включены", "enable": "остались отключены",
            "remove": "не удалены", "set": "не изменены"}[p.verb]
    if failed:
        return LineCheck(i, cmd, "missing", f"{failed} из {len(targets)} записей {what}")
    return LineCheck(i, cmd, "ok", f"записей: {len(targets)}")


def for_plan(plan: dict[str, Any], last_collected: str | None) -> dict[str, Any] | None:
    """Verification of an applied plan, or None when there is nothing to verify."""
    if plan.get("status") != "applied" or not plan.get("applied_at"):
        return None
    done = datetime.fromisoformat(plan["applied_at"])
    history = store.history(plan["device_slug"], limit=500)          # newest first
    before = next((h for h in history if datetime.fromisoformat(h["date"]) <= done), None)
    later = [h for h in history if datetime.fromisoformat(h["date"]) > done]
    if before is None:
        return None
    if later:
        after_sha, after_date = later[-1]["sha"], later[-1]["date"]
    elif last_collected and datetime.fromisoformat(last_collected) > done:
        after_sha, after_date = before["sha"], last_collected      # collected, nothing changed
    else:
        return {"state": "waiting"}
    commands = [c for c in plan["commands"].splitlines() if c.strip() and not c.strip().startswith("#")]
    lines = check(commands, store.show(plan["device_slug"], before["sha"]) or "",
                  store.show(plan["device_slug"], after_sha) or "")
    return {"state": "checked", "lines": lines, "after_date": after_date,
            "missing": sum(1 for x in lines if x.status == "missing"),
            "unknown": sum(1 for x in lines if x.status == "unknown")}
