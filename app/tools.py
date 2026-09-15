"""Tools the LLM may call. Read-only in phase 2.

Every tool returns text, is size-capped (config.TOOL_MAX_CHARS) and runs the scrubber on
anything that came off a router. Device references are resolved leniently (slug, name,
identity or host) because the model will use whatever it saw in the fleet map.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable

from . import db, facts as facts_mod, live, rsc, scrub, store
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


# A rule reading "dst-address-list=Srv-list" decides nothing without the list's members, and
# get_sections returns only the paths asked for - so whoever asks for the rules gets the lists
# those rules name, or they conclude the rule is unrelated and propose a change that cannot work.
_LIST_REFS: dict[str, tuple[str, ...]] = {
    "/ip/firewall/address-list": ("address-list", "src-address-list", "dst-address-list"),
    "/interface/list/member": ("interface-list", "in-interface-list", "out-interface-list"),
}
LIST_EXPANSION_MAX_LINES = 40


def referenced_lists(text: str, lines: list[str], asked: list[str]) -> list[str]:
    """Member blocks for the named lists `lines` reference but `asked` does not already cover."""
    want = [rsc.normalize_path(p) for p in asked]
    refs = rsc.parse("\n".join(lines))
    entries = rsc.parse(text)
    blocks: list[str] = []
    for path, attrs in _LIST_REFS.items():
        if any(path == w or path.startswith(w + "/") for w in want):
            continue
        # "!Admin-list" negates the match but references the same list.
        names = {v.lstrip("!") for e in refs for a in attrs if (v := e.args.get(a, "").lstrip("!"))}
        if not names:
            continue
        out: list[str] = []
        for name in sorted(names):
            members = [e.raw for e in entries if e.path == path and e.args.get("list", "") == name]
            if not members:
                continue
            # Capped per list, not per block: a long list must not crowd out a short one.
            if len(members) > LIST_EXPANSION_MAX_LINES:
                out.append(f"# {name}: showing {LIST_EXPANSION_MAX_LINES} of {len(members)} entries")
                members = members[:LIST_EXPANSION_MAX_LINES]
            out.extend(members)
        if out:
            blocks.append(f"# {path} - members of the lists referenced above "
                          f"(request {path} directly for the full lists)\n" + "\n".join(out))
    return blocks


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
    body = "\n".join(lines)
    for block in referenced_lists(text, lines, paths):
        body += "\n\n" + block
    return _cap(f"# {dev['slug']} - {', '.join(paths)}\n" + _clean(body))


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


async def get_live_state(device: str = "", query: str = "", match: str = "", limit: int = 50, **_: Any) -> str:
    """Live router state. Async because it opens an SSH session, unlike the stored-config tools."""
    if not query:
        raise ToolError("'query' is required. Valid keys:\n" + live.describe())
    dev = _devices([device])[0]
    try:
        raw = await live.fetch(dev, query)
        body, shown, total = live.filter_lines(raw, match or None, limit, live.QUERIES[query].tail)
    except live.LiveError as exc:
        raise ToolError(str(exc)) from exc
    q = live.QUERIES[query]
    head = f"# {dev['slug']} — {q.label} (live, `{q.command}`)"
    if match:
        head += f"\n# фильтр /{match}/: {shown} из {total} строк"
    elif shown < total:
        head += f"\n# показано {shown} из {total} строк"
    return _cap(f"{head}\n{body}" if body else f"{head}\n(пусто)")


def propose_change(device: str = "", title: str = "", rationale: str = "", commands: str = "", **_: Any) -> str:
    """Queue a change plan for human approval. This tool never applies anything."""
    from . import changes

    if not commands.strip():
        raise ToolError("'commands' is required: RouterOS commands, one per line")
    if not rationale.strip():
        raise ToolError("'rationale' is required: explain what the change does and why")
    dev = _devices([device])[0]

    verdict = changes.validate(commands)
    findings = [{"line": f.line, "command": f.command, "reason": f.reason}
                for f in (verdict.blocked or verdict.risky)]

    if not verdict.ok:
        # Rejected plans are not stored: nothing to approve, and it keeps the queue meaningful.
        return ("ОТКЛОНЕНО валидатором, план не поставлен в очередь:\n"
                + "\n".join(f"  строка {f.line}: {f.reason}" for f in verdict.blocked)
                + "\n\nЭти операции недоступны автоматическому изменению — их выполняет человек "
                  "на устройстве. Предложи другой способ добиться цели или объясни пользователю, "
                  "что нужно сделать вручную.")

    plan_id = db.create_plan({
        "device_id": dev["id"], "created_by": "agent", "title": (title or "Изменение конфигурации")[:120],
        "rationale": rationale.strip(), "commands": "\n".join(verdict.commands),
        "risk": verdict.risk, "findings": json.dumps(findings, ensure_ascii=False), "status": "pending",
    })
    note = ""
    if verdict.risky:
        note = ("\nВНИМАНИЕ, помечено как рискованное:\n"
                + "\n".join(f"  строка {f.line}: {f.reason}" for f in verdict.risky))
    return (f"План #{plan_id} поставлен в очередь для {dev['slug']} "
            f"({len(verdict.commands)} команд, риск: {verdict.risk}).{note}\n\n"
            f"Ничего не применено и применено не будет: автоматическое применение отключено. "
            f"Оператор откроет раздел «Изменения», скопирует команды и выполнит их сам в Winbox. "
            f"Сообщи пользователю, что план готов, и кратко перечисли, что он делает и на что "
            f"обратить внимание при выполнении.")


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
    "get_live_state": get_live_state,
    "propose_change": propose_change,
}

# Tools that must be awaited - they talk to a router instead of reading the local store.
ASYNC_TOOLS = {"get_live_state"}

# propose_change only writes a row to the approval queue. Nothing in this registry can change a
# router: applying is a UI action performed by a person. See apply.py.

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
        "description": "Return the exact RouterOS export lines for one or more configuration sections of a device. This is the main tool for answering 'how is X configured'. Paths may be written '/ip firewall filter' or '/ip/firewall/filter'; a prefix returns all sub-sections. When the returned lines reference a named address-list or interface-list, that list's members are appended automatically, so you can tell whether a rule actually matches the addresses you care about.",
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
    {
        "name": "get_live_state",
        "description": (
            "Read what a router is doing RIGHT NOW over SSH - state that never appears in the "
            "stored configuration: active routes, ARP, DHCP leases, the log, interface counters, "
            "connection tracking, associated Wi-Fi clients, WireGuard handshakes, firewall rule "
            "hit counters. Use it when the question is about current behaviour, symptoms or "
            "'why is X not working', rather than about how something is configured. Slower than "
            "the stored-config tools and it touches the live device, so use it deliberately.\n\n"
            "Valid 'query' values:\n" + live.describe()
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device slug, name, identity or host."},
                "query": {"type": "string", "enum": sorted(live.QUERIES), "description": "Which live view to read."},
                "match": {"type": "string", "description": "Optional case-insensitive regex; only matching lines are returned. Filtering happens locally, so it never changes the command sent to the router."},
                "limit": {"type": "integer", "description": "Max lines to return (1-200, default 50). Logs return the newest lines."},
            },
            "required": ["device", "query"],
        },
    },
    {
        "name": "propose_change",
        "description": (
            "Propose a configuration change for a device. This places a plan in a queue for a "
            "human to review - it NEVER applies anything, and you cannot apply it yourself. "
            "Automatic applying is currently disabled entirely, so the operator will run the "
            "commands by hand in Winbox; write them so they can be pasted as-is. Use this when "
            "the user asks for a change rather than a question.\n\n"
            "Write one RouterOS command per line, exactly as they would be typed on the device. "
            "A deterministic validator checks the plan before it is queued and rejects anything "
            "destructive (reboots, configuration resets, user management, scripts, schedulers, firmware, file "
            "operations, command chaining). Do not try to work around a rejection - report it to "
            "the user and suggest doing that part by hand.\n\n"
            "Read the current configuration first so the change fits what is actually there, and "
            "say plainly in 'rationale' what will change and what could break."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device slug, name, identity or host."},
                "title": {"type": "string", "description": "Short title for the queue, e.g. 'Открыть SSH для офисной сети'."},
                "rationale": {"type": "string", "description": "What the change does, why, and the risks. The operator reads this before approving."},
                "commands": {"type": "string", "description": "RouterOS commands, one per line. No shell, no semicolons, no scripting expressions."},
            },
            "required": ["device", "title", "rationale", "commands"],
        },
    },
]


async def call(name: str, arguments: dict[str, Any]) -> str:
    handler = REGISTRY.get(name)
    if handler is None:
        return f"ERROR: unknown tool '{name}'. Available: {', '.join(REGISTRY)}"
    try:
        if name in ASYNC_TOOLS:
            return await handler(**(arguments or {}))
        return handler(**(arguments or {}))
    except ToolError as exc:
        return f"ERROR: {exc}"
    except TypeError as exc:
        return f"ERROR: bad arguments for {name}: {exc}"
    except Exception as exc:  # noqa: BLE001 - never let a tool crash the chat
        return f"ERROR: {name} failed: {type(exc).__name__}: {exc}"
