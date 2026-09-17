"""Deterministic configuration audit: findings with the evidence attached.

Every finding points at the export line it is about, so a person can verify it in Winbox without
trusting a model. Nothing here talks to a router - an audit must be instant and must still work on
a device that is currently unreachable. Checks that need live counters (a rule that has never
matched) deliberately live elsewhere: they need an SSH round-trip and a caveat about when the
counters were last reset.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

from . import rsc

STALE_DAYS = 90

_ADDRESS_ATTRS = ("src-address-list", "dst-address-list")
_INTERFACE_ATTRS = ("interface-list", "in-interface-list", "out-interface-list")
# Only rule tables are checked: elsewhere (e.g. /ppp profile interface-list=) the same attribute
# names a list to *fill*, not one to match on.
_RULE_TABLES = frozenset(
    [f"/{fam}/firewall/{t}" for fam in ("ip", "ipv6") for t in ("filter", "nat", "mangle", "raw")]
    + ["/interface/bridge/filter", "/interface/bridge/nat"]
)
_BUILTIN_INTERFACE_LISTS = frozenset({"all", "none", "dynamic", "static"})
# Attributes that put members into a list at runtime; those members never appear in /export.
_ADDRESS_FILLERS = ("address-list", "address-lists")
_INTERFACE_FILLERS = ("interface-list", "lan-interface-list", "wan-interface-list",
                      "internet-interface-list")

# Attributes that say what a rule does; everything else narrows what it matches.
_NON_MATCH = frozenset({
    "action", "comment", "disabled", "log", "log-prefix", "jump-target", "place-before",
    "address-list", "address-list-timeout", "to-addresses", "to-ports", "passthrough",
    "new-connection-mark", "new-packet-mark", "new-routing-mark", "new-dscp", "new-mss",
})
_TERMINAL = frozenset({"accept", "drop", "reject", "tarpit"})
_ORDERED_CHAINS = ("/ip/firewall/filter", "/ip/firewall/raw")
# Matched from the start of a word, so "latest", "threshold" and "template" do not count;
# the stems may continue ("testing", "временно"), the short words may not ("temperature").
_JUNK_RE = re.compile(
    r"(?<![^\W\d_])(?:(?:udalit|удалить|test|тест|времен)|(?:udal|tmp|temp|old|старое)(?![^\W\d_]))",
    re.IGNORECASE,
)
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str
    line_no: int = 0
    command: str = ""


def _matchers(e: rsc.Entry) -> dict[str, str]:
    return {k: v for k, v in e.args.items() if k not in _NON_MATCH}


def _plural(n: int, one: str, few: str, many: str) -> str:
    if n % 100 // 10 == 1:
        return many
    return {1: one, 2: few, 3: few, 4: few}.get(n % 10, many)


def _family(path: str) -> str:
    return "ipv6" if path.startswith("/ipv6/") else "ip"


def _names(value: str) -> list[str]:
    return [n for n in value.split(",") if n]


def dangling_list_refs(entries: list[rsc.Entry]) -> list[Finding]:
    """Rules that match on a list with no enabled members."""
    # Keys: ("ip"|"ipv6", name) for address lists, ("if", name) for interface lists.
    members: dict[tuple[str, str], list[rsc.Entry]] = {}
    filled: set[tuple[str, str]] = set()
    for e in entries:
        if e.verb != "add":
            continue
        name = e.args.get("list", "")
        if name and e.path in ("/ip/firewall/address-list", "/ipv6/firewall/address-list"):
            members.setdefault((_family(e.path), name), []).append(e)
        elif name and e.path == "/interface/list/member":
            members.setdefault(("if", name), []).append(e)
        elif e.path == "/interface/list" and e.args.get("include") and e.args.get("name"):
            filled.add(("if", e.args["name"]))

    for e in entries:
        if e.is_disabled() or e.verb not in ("add", "set"):
            continue
        for attr in _ADDRESS_FILLERS:
            filled.update((_family(e.path), n) for n in _names(e.args.get(attr, "")))
        if e.path not in _RULE_TABLES:
            for attr in _INTERFACE_FILLERS:
                filled.update(("if", n) for n in _names(e.args.get(attr, "")))

    out: list[Finding] = []
    for e in entries:
        if e.verb != "add" or e.is_disabled() or e.path not in _RULE_TABLES:
            continue
        for attr in _ADDRESS_ATTRS + _INTERFACE_ATTRS:
            raw = e.args.get(attr, "")
            if not raw:
                continue
            negated = raw.startswith("!")
            name = raw.lstrip("!")
            key = ("if", name) if attr in _INTERFACE_ATTRS else (_family(e.path), name)
            if key in filled or (key[0] == "if" and name in _BUILTIN_INTERFACE_LISTS):
                continue
            known = members.get(key, [])
            if any(not m.is_disabled() for m in known):
                continue
            if not known:
                what = f"списка «{name}» нет в конфиге"
            else:
                what = f"все записи списка «{name}» ({len(known)} шт.) отключены"
            if negated:
                detail = (f"Правило исключает {attr}=!{name}, но {what}. "
                          f"Исключать нечего, поэтому правило применяется ко всему трафику, "
                          f"который подходит под остальные условия.")
                severity = "high"
            else:
                detail = (f"Правило срабатывает только на {attr}={name}, но {what}. "
                          f"Сейчас оно не может сработать никогда.")
                severity = "medium"
            out.append(Finding("dangling-list", severity,
                               f"Ссылка на пустой список «{name}»", detail, e.line_no, e.raw))
    return out


def shadowed_rules(entries: list[rsc.Entry]) -> list[Finding]:
    """Terminal rules that make every later rule they cover unreachable."""
    chains: dict[tuple[str, str], list[rsc.Entry]] = {}
    for e in entries:
        if e.verb == "add" and e.path in _ORDERED_CHAINS and not e.is_disabled():
            chains.setdefault((e.path, e.args.get("chain", "")), []).append(e)

    out: list[Finding] = []
    for (path, chain), rules in chains.items():
        for i, earlier in enumerate(rules):
            if earlier.args.get("action", "") not in _TERMINAL:
                continue
            conditions = _matchers(earlier)
            # Everything the earlier rule constrains, the later rule constrains identically - so
            # every packet reaching the later rule was already decided by the earlier one.
            covered = [r for r in rules[i + 1:]
                       if all(_matchers(r).get(k) == v for k, v in conditions.items())]
            if not covered:
                continue
            lines = ", ".join(str(r.line_no) for r in covered[:5])
            if len(covered) > 5:
                lines += f" и ещё {len(covered) - 5}"
            n = len(covered)
            word = _plural(n, "правило", "правила", "правил")
            catch_all = set(conditions) <= {"chain"}
            detail = (f"Правило {earlier.args.get('action')} в chain={chain} "
                      f"{'не имеет других условий и ' if catch_all else ''}"
                      f"перекрывает {n} {word} ниже (строки {lines}): до них трафик не доходит. "
                      f"Либо нижние правила лишние, либо это правило шире, чем задумано.")
            out.append(Finding("shadowed-rules", "high" if catch_all else "medium",
                               f"Перекрывает {n} {word} ниже", detail,
                               earlier.line_no, earlier.raw))
    return out


def stale_disabled(entries: list[rsc.Entry], dates: dict[int, str],
                   today: date | None = None) -> list[Finding]:
    """Disabled entries that have been sitting untouched, by the date git last saw them change."""
    today = today or date.today()
    out: list[Finding] = []
    for e in entries:
        if not e.is_disabled():
            continue
        comment = e.args.get("comment", "")
        junk = bool(_JUNK_RE.search(comment))
        seen = dates.get(e.line_no, "")
        age = (today - date.fromisoformat(seen)).days if seen else None
        if junk:
            detail = f"Комментарий помечает запись как временную: «{comment}»."
            if age is not None:
                detail += f" В этом виде с {seen}."
        elif age is not None and age >= STALE_DAYS:
            detail = f"Строка не менялась с {seen} ({age} дн.)."
            if comment:
                detail += f" Комментарий: «{comment}»."
        else:
            continue
        out.append(Finding("stale-disabled", "medium" if junk else "low",
                           "Отключено и забыто", detail, e.line_no, e.raw))
    return out


def audit(export_text: str, dates: dict[int, str] | None = None,
          today: date | None = None) -> list[Finding]:
    entries = rsc.parse(export_text)
    found = (dangling_list_refs(entries)
             + shadowed_rules(entries)
             + stale_disabled(entries, dates or {}, today))
    return sorted(found, key=lambda f: (_SEVERITY_ORDER[f.severity], f.line_no))
