"""Parser for ``/export terse`` output.

RouterOS 7 (and 6 with ``terse``) prints one command per line with its full menu path::

    /ip firewall filter add action=accept chain=input comment="defconf: accept established"
    /interface ethernet set [ find default-name=ether1 ] name=WAN

Both the collector (header stripping) and the agent tools (section lookup, search) rely on
that one-line-per-command shape. Paths are normalised to slash form ("/ip/firewall/filter")
so callers may write either "/ip firewall filter" or "/ip/firewall/filter".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_LINE = re.compile(r"^(?P<path>/[a-z0-9][a-z0-9 /-]*?)\s+(?P<verb>add|set|remove|enable|disable|print|import)\b\s*(?P<rest>.*)$")
_TOKEN = re.compile(r'([\w.-]+)=("(?:[^"\\]|\\.)*"|\S*)')
_SELECTOR = re.compile(r"^\[\s*(.*?)\s*\]\s*")


@dataclass
class Entry:
    path: str            # normalised: /ip/firewall/filter
    verb: str
    args: dict[str, str] = field(default_factory=dict)
    selector: str = ""   # e.g. "find default-name=ether1" (v7) or a numeric index (v6)
    raw: str = ""
    line_no: int = 0

    @property
    def name(self) -> str:
        """Best display name of an item: name=, or default-name from a selector."""
        if "name" in self.args:
            return self.args["name"]
        m = re.search(r"default-name=(\S+)", self.selector)
        return m.group(1) if m else ""

    def is_disabled(self) -> bool:
        return self.args.get("disabled") == "yes"


def normalize_path(path: str) -> str:
    parts = [p for p in re.split(r"[ /]+", path.strip()) if p]
    return "/" + "/".join(parts)


def strip_header(text: str) -> str:
    """Drop the leading ``# ...`` banner (timestamp, software id, model, serial) so exports diff cleanly."""
    lines = text.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines) and (lines[i].startswith("#") or not lines[i].strip()):
        i += 1
    return "\n".join(l.rstrip() for l in lines[i:]).strip("\n") + "\n"


def parse_args(rest: str) -> tuple[str, dict[str, str]]:
    selector = ""
    m = _SELECTOR.match(rest)
    if m:
        selector, rest = m.group(1), rest[m.end():]
    else:
        m2 = re.match(r"^(\d+)\s+", rest)
        if m2:
            selector, rest = m2.group(1), rest[m2.end():]
    args: dict[str, str] = {}
    for k, v in _TOKEN.findall(rest):
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            v = v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        args[k] = v
    return selector, args


def parse(text: str) -> list[Entry]:
    entries: list[Entry] = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            continue
        selector, args = parse_args(m.group("rest"))
        entries.append(Entry(normalize_path(m.group("path")), m.group("verb"), args, selector, line, i))
    return entries


def section_lines(text: str, prefixes: list[str]) -> list[str]:
    """Lines whose path starts with any of the given (normalised) prefixes."""
    want = [normalize_path(p) for p in prefixes]
    out = []
    for line in text.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        p = normalize_path(m.group("path"))
        if any(p == w or p.startswith(w + "/") for w in want):
            out.append(line)
    return out


def section_index(text: str) -> dict[str, int]:
    """path -> number of commands, in first-seen order."""
    idx: dict[str, int] = {}
    for e in parse(text):
        idx[e.path] = idx.get(e.path, 0) + 1
    return idx
