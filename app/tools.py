"""Tools the LLM may call. Read-only in phase 2.

Every tool returns text, is size-capped (config.TOOL_MAX_CHARS) and runs the scrubber on
anything that came off a router. Device references are resolved leniently (slug, name,
identity or host) because the model will use whatever it saw in the fleet map.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable

from . import db, facts as facts_mod, rsc, scrub, store
from .config import SEARCH_MAX_PER_DEVICE, SEARCH_MAX_TOTAL, TOOL_MAX_CHARS


class ToolError(Exception):
    """Message goes back to the model as the tool result, so it can correct itself."""


def _cap(text: str, limit: int = TOOL_MAX_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[... truncated at {limit} characters; narrow the request]"


def _clean(text: str) -> str:
    return scrub.scrub(text)[0]


def _devices(refs: list[str] | None) -> list[Any]:
    if not refs:
        return [d for d in db.list_devices() if store.read_export(d["slug"])]
    out = []
    for ref in refs:
        dev = db.find_device(ref)
        if dev is None:
            known = ", ".join(d["slug"] for d in db.list_devices()) or "none"
            raise ToolError(f"unknown device '{ref}'. Known devices: {known}")
        out.append(dev)
    return out


def _export_or_fail(dev: Any) -> str:
    text = store.read_export(dev["slug"])
    if text is None:
        raise ToolError(f"no config collected yet for '{dev['slug']}' (status: {dev['status']})")
    return text


# ---------------------------------------------------------------- tool implementations

def list_devices(**_: Any) -> str:
    rows = db.list_devices()
    if not rows:
        return "No devices configured yet."
    out = []
    for d in rows:
        fx = store.read_facts(d["slug"])
        out.append(facts_mod.summary(dict(d), json.loads(fx) if fx else None))
    return _cap("\n".join(out))


def get_sections(device: str = "", paths: list[str] | None = None, **_: Any) -> str:
    if not paths:
        raise ToolError("'paths' is required, e.g. [\"/ip/firewall/filter\", \"/ip/address\"]")
    dev = _devices([device])[0]
    text = _export_or_fail(dev)
    lines = rsc.section_lines(text, paths)
    if not lines:
        idx = rsc.section_index(text)
        near = [p for p in idx if any(rsc.normalize_path(w).strip("/").split("/")[0] in p for w in paths)]
        hint = f" Closest sections present: {', '.join(near[:15])}" if near else f" Sections present: {', '.join(list(idx)[:40])}"
        return f"No configuration under {paths} on {dev['slug']}.{hint}"
    return _cap(f"# {dev['slug']} - {', '.join(paths)}\n" + _clean("\n".join(lines)))


def search_config(pattern: str = "", devices: list[str] | None = None, context: int = 0, **_: Any) -> str:
    if not pattern:
        raise ToolError("'pattern' is required")
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ToolError(f"invalid regex: {exc}") from exc
    targets = _devices(devices)
    blocks, total, hidden = [], 0, 0
    for dev in targets:
        text = store.read_export(dev["slug"])
        if text is None:
            continue
        lines = text.splitlines()
        hits = [i for i, l in enumerate(lines) if rx.search(l)]
        if not hits:
            continue
        shown = hits[:SEARCH_MAX_PER_DEVICE]
        hidden += len(hits) - len(shown) + max(0, total + len(shown) - SEARCH_MAX_TOTAL)
        room = max(0, SEARCH_MAX_TOTAL - total)
        shown = shown[:room]
        if not shown:
            continue
        total += len(shown)
        picked: list[str] = []
        for i in shown:
            lo, hi = max(0, i - context), min(len(lines), i + context + 1)
            picked.extend(lines[lo:hi])
        blocks.append(f"## {dev['slug']} ({len(hits)} match{'es' if len(hits) != 1 else ''})\n" + _clean("\n".join(picked)))
    if not blocks:
        return f"No matches for /{pattern}/ in {len(targets)} device config(s)."
    tail = f"\n\n[{hidden} more matches hidden - narrow the pattern or pass 'devices']" if hidden else ""
    return _cap("\n\n".join(blocks) + tail)


def get_full_export(device: str = "", **_: Any) -> str:
    dev = _devices([device])[0]
    text = _export_or_fail(dev)
    return _cap(f"# {dev['slug']} full export ({len(text.splitlines())} lines)\n" + _clean(text))


def list_sections(device: str = "", **_: Any) -> str:
    dev = _devices([device])[0]
    idx = rsc.section_index(_export_or_fail(dev))
    body = "\n".join(f"{p}  ({n})" for p, n in sorted(idx.items()))
    return _cap(f"# {dev['slug']} - {len(idx)} sections (path, command count)\n{body}")


def get_device_facts(device: str = "", **_: Any) -> str:
    dev = _devices([device])[0]
    raw = store.read_facts(dev["slug"])
    if raw is None:
        raise ToolError(f"no facts for '{dev['slug']}' yet")
    return _cap(f"# {dev['slug']} structured facts\n{raw}")


def config_history(device: str = "", limit: int = 10, **_: Any) -> str:
    dev = _devices([device])[0]
    hist = store.history(dev["slug"], limit=min(int(limit or 10), 50))
    if not hist:
        return f"No recorded config changes for {dev['slug']}."
    body = "\n".join(f"{h['short']}  {h['date']}  {h['subject']}" for h in hist)
    return _cap(f"# {dev['slug']} config change history (newest first)\n{body}\n\nUse config_diff(device, commit) to see what changed.")


def config_diff(device: str = "", commit: str = "", **_: Any) -> str:
    dev = _devices([device])[0]
    if not commit:
        hist = store.history(dev["slug"], limit=1)
        if not hist:
            return f"No commits touching {dev['slug']}."
        commit = hist[0]["sha"]
    if not re.fullmatch(r"[0-9a-fA-F]{4,40}", commit):
        raise ToolError("'commit' must be a git sha from config_history")
    d = store.diff_prev(dev["slug"], commit)
    if not d.strip():
        return f"Commit {commit[:8]} did not change {dev['slug']} (or it is the first commit)."
    return _cap(f"# {dev['slug']} diff at {commit[:8]}\n" + _clean(d))


def fleet_summary(**_: Any) -> str:
    rows = db.list_devices()
    if not rows:
        return "No devices configured."
    sites: dict[str, list[str]] = {}
    subnet_owner: dict[str, list[str]] = {}
    tunnels: list[str] = []
    for d in rows:
        raw = store.read_facts(d["slug"])
        sites.setdefault(d["site"] or "-", []).append(d["slug"])
        if not raw:
            continue
        fx = json.loads(raw)
        for s in fx.get("subnets", []):
            subnet_owner.setdefault(s, []).append(d["slug"])
        for t in fx.get("tunnels", []):
            if t.get("peer"):
                tunnels.append(f"{d['slug']} --{t['type']}--> {t['peer']}" + (" (disabled)" if t.get("disabled") else ""))
    parts = ["# Fleet overview", f"{len(rows)} devices in {len(sites)} site(s)"]
    parts.append("\n## Sites\n" + "\n".join(f"{s}: {', '.join(v)}" for s, v in sorted(sites.items())))
    dup = {s: v for s, v in subnet_owner.items() if len(v) > 1}
    parts.append("\n## Subnets\n" + "\n".join(f"{s}: {', '.join(v)}" for s, v in sorted(subnet_owner.items())))
    if dup:
        parts.append("\n## Subnets present on more than one device\n" + "\n".join(f"{s}: {', '.join(v)}" for s, v in sorted(dup.items())))
    parts.append("\n## Tunnel endpoints\n" + ("\n".join(sorted(set(tunnels))) or "none"))
    return _cap("\n".join(parts))


# ---------------------------------------------------------------- registry

Handler = Callable[..., str]

REGISTRY: dict[str, Handler] = {
    "list_devices": list_devices,
    "fleet_summary": fleet_summary,
    "list_sections": list_sections,
    "get_sections": get_sections,
    "search_config": search_config,
    "get_device_facts": get_device_facts,
    "get_full_export": get_full_export,
    "config_history": config_history,
    "config_diff": config_diff,
}

SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "list_devices",
        "description": "List every managed MikroTik with a compact summary (model, RouterOS version, site, WAN, VLANs, subnets, tunnels, routing, firewall counts). Start here when you need to know what exists.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "fleet_summary",
        "description": "Cross-device overview: sites, which subnets live where, duplicate subnets, and all tunnel endpoints. Use for questions about connectivity between sites or about the network as a whole.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "list_sections",
        "description": "List the configuration sections present on one device with the number of commands in each (e.g. /ip/firewall/filter (47)). Use it to discover the exact path before calling get_sections.",
        "parameters": {
            "type": "object",
            "properties": {"device": {"type": "string", "description": "Device slug, name, identity or host."}},
            "required": ["device"],
        },
    },
    {
        "name": "get_sections",
        "description": "Return the exact RouterOS export lines for one or more configuration sections of a device. This is the main tool for answering 'how is X configured'. Paths may be written '/ip firewall filter' or '/ip/firewall/filter'; a prefix returns all sub-sections.",
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device slug, name, identity or host."},
                "paths": {"type": "array", "items": {"type": "string"}, "description": "Menu paths, e.g. [\"/ip/firewall/nat\", \"/ip/address\"]."},
            },
            "required": ["device", "paths"],
        },
    },
    {
        "name": "search_config",
        "description": "Case-insensitive regex search across stored configs. Use it to locate a subnet, interface, comment, peer address or feature when you do not know which device or section holds it. Results are capped, so prefer a specific pattern.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regular expression, e.g. \"10\\\\.10\\\\.4\\\\.\" or \"wireguard\"."},
                "devices": {"type": "array", "items": {"type": "string"}, "description": "Restrict to these devices. Omit to search all."},
                "context": {"type": "integer", "description": "Lines of context around each hit (0-3, default 0)."},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "get_device_facts",
        "description": "Structured JSON facts for one device (interfaces, VLANs, addresses, subnets, DHCP, firewall counts, routing protocols, tunnels, services). Cheaper and more reliable than parsing the export yourself.",
        "parameters": {
            "type": "object",
            "properties": {"device": {"type": "string"}},
            "required": ["device"],
        },
    },
    {
        "name": "get_full_export",
        "description": "The complete export of one device. Expensive - only use it when the question genuinely spans the whole configuration and get_sections/search_config are not enough.",
        "parameters": {
            "type": "object",
            "properties": {"device": {"type": "string"}},
            "required": ["device"],
        },
    },
    {
        "name": "config_history",
        "description": "Recent commits that changed a device's configuration, newest first, with git shas to feed to config_diff. Use it for 'when did this change' or 'what changed recently'.",
        "parameters": {
            "type": "object",
            "properties": {"device": {"type": "string"}, "limit": {"type": "integer", "description": "Max commits (default 10)."}},
            "required": ["device"],
        },
    },
    {
        "name": "config_diff",
        "description": "Unified diff showing exactly what changed on a device in a given commit (default: the most recent one).",
        "parameters": {
            "type": "object",
            "properties": {"device": {"type": "string"}, "commit": {"type": "string", "description": "Git sha from config_history; omit for the latest."}},
            "required": ["device"],
        },
    },
]


def call(name: str, arguments: dict[str, Any]) -> str:
    handler = REGISTRY.get(name)
    if handler is None:
        return f"ERROR: unknown tool '{name}'. Available: {', '.join(REGISTRY)}"
    try:
        return handler(**(arguments or {}))
    except ToolError as exc:
        return f"ERROR: {exc}"
    except TypeError as exc:
        return f"ERROR: bad arguments for {name}: {exc}"
    except Exception as exc:  # noqa: BLE001 - never let a tool crash the chat
        return f"ERROR: {name} failed: {type(exc).__name__}: {exc}"
