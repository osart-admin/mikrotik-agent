"""Live state queries: what the router is doing right now, as opposed to how it is configured.

Safety model - the command is never built from model input:

* The caller passes a **key** from ``QUERIES``; the command is a literal constant looked up in
  that table. Nothing is interpolated into it, so there is no RouterOS command injection surface
  no matter what the model emits.
* Filtering happens in Python over the returned lines, not in a ``where`` clause on the router,
  for the same reason.
* Every command here is a ``print`` covered by the ``read`` policy - the agent's group grants
  ``ssh,read`` and nothing else, so none of this needs ``test`` (ping/traceroute/bandwidth-test).

Results are cached briefly so a chain of tool calls in one answer cannot hammer a router.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any

from . import collector, scrub
from .ssh import RouterSSH, SSHError

CACHE_TTL = 15.0
MAX_LINES = 200
# RouterOS prints a flags legend and a column header even for `terse` output, where every value
# is already key=value. They are pure noise that would otherwise eat into the line budget.
_NOISE = re.compile(r"^(Flags:|Columns:|#\s+[A-Z][A-Z0-9 ,/-]*$)")
_cache: dict[tuple[int, str], tuple[float, str]] = {}


@dataclass(frozen=True)
class Query:
    key: str
    label: str
    command: str      # literal, never formatted with caller input
    hint: str = ""
    tail: bool = False  # keep the LAST n lines rather than the first (logs)
    needs: str = ""     # extra RouterOS policy beyond 'read', if the menu demands one


QUERIES: dict[str, Query] = {q.key: q for q in [
    Query("routes", "Таблица маршрутов", "/ip route print terse",
          "Active routes including dynamic ones, which /export never shows."),
    Query("arp", "ARP-таблица", "/ip arp print terse", "Which MACs are seen on which interface."),
    Query("dhcp_leases", "DHCP-аренды", "/ip dhcp-server lease print terse",
          "Issued addresses, bound/waiting state, hostnames."),
    Query("dhcp_client", "DHCP-клиент (WAN)", "/ip dhcp-client print terse",
          "Address obtained on WAN interfaces and its status."),
    # Verified on RouterOS 7.22: /log print is refused with policy=ssh,read and works once
    # 'test' is granted, unlike every other entry here.
    Query("log", "Системный лог", "/log print",
          "Recent events. Use 'match' to filter, e.g. dhcp, wireless, error.", tail=True, needs="test"),
    Query("interfaces", "Статистика интерфейсов", "/interface print stats terse",
          "Per-interface rx/tx bytes and packets, running state."),
    Query("interface_traffic", "Текущий трафик", "/interface monitor-traffic [find] once",
          "Instantaneous rx/tx rate per interface."),
    Query("connections", "Таблица соединений", "/ip firewall connection print terse",
          "Live connection tracking entries. Large - always pass 'match'."),
    Query("connections_count", "Число соединений", "/ip firewall connection print count-only"),
    Query("wifi_clients", "Клиенты Wi-Fi", "/interface wifi registration-table print terse",
          "Associated stations with signal, rate and uptime."),
    Query("wifi_clients_legacy", "Клиенты Wi-Fi (старый драйвер)", "/interface wireless registration-table print terse",
          "For RouterOS 6 / legacy wireless package."),
    Query("ppp_active", "Активные PPP-сессии", "/ppp active print terse"),
    Query("wireguard_peers", "Пиры WireGuard", "/interface wireguard peers print terse",
          "Last handshake and transferred bytes - shows whether a tunnel is actually up."),
    Query("ipsec_active", "Активные пиры IPsec", "/ip ipsec active-peers print terse"),
    Query("ipsec_sa", "IPsec SA", "/ip ipsec installed-sa print terse"),
    Query("firewall_filter_stats", "Счётчики firewall filter", "/ip firewall filter print stats terse",
          "Packet/byte counters per rule - shows which rules actually fire."),
    Query("firewall_nat_stats", "Счётчики NAT", "/ip firewall nat print stats terse"),
    Query("firewall_mangle_stats", "Счётчики mangle", "/ip firewall mangle print stats terse"),
    Query("address_lists", "Динамические address-list", "/ip firewall address-list print terse",
          "Includes dynamically added entries that /export omits."),
    Query("neighbors", "Соседи (MNDP/CDP)", "/ip neighbor print terse",
          "Directly attached MikroTik/CDP devices - useful for topology."),
    Query("health", "Датчики", "/system health print", "Temperature, voltage where supported."),
    Query("resource", "Ресурсы", "/system resource print", "CPU, memory, uptime, version."),
    Query("routerboard", "Плата", "/system routerboard print"),
    Query("users_active", "Активные сессии", "/user active print terse", "Who is logged into the router now."),
    Query("dns_cache", "DNS-кэш", "/ip dns cache print terse"),
    Query("queues", "Очереди", "/queue simple print stats terse"),
]}


def describe() -> str:
    return "\n".join(
        f"{q.key} — {q.label}" + (f". {q.hint}" if q.hint else "")
        + (f" (requires the '{q.needs}' policy, which the read-only group may not have)" if q.needs else "")
        for q in QUERIES.values()
    )


class LiveError(Exception):
    pass


async def fetch(device: Any, key: str) -> str:
    """Run one whitelisted command on a device, with a short cache."""
    query = QUERIES.get(key)
    if query is None:
        raise LiveError(f"unknown query '{key}'. Valid: {', '.join(QUERIES)}")
    if not device["enabled"]:
        raise LiveError(f"device '{device['slug']}' is disabled")

    cache_key = (device["id"], key)
    hit = _cache.get(cache_key)
    now = time.monotonic()
    if hit and now - hit[0] < CACHE_TTL:
        return hit[1]

    try:
        async with RouterSSH(device["host"], device["port"], collector.credentials_for(device)) as r:
            out = await r.run(query.command, timeout=30)
    except SSHError as exc:
        raise LiveError(f"{device['slug']} unreachable ({exc.kind}): {exc.message}") from exc

    low = out.lower()
    if "not enough permissions" in low:
        extra = f" This menu requires the '{query.needs}' policy." if query.needs else ""
        raise LiveError(
            f"router refused '{query.command}' for user {device['username']}: the agent's group "
            f"grants only ssh,read.{extra} Ask the operator to decide whether to widen the group."
        )
    # An unsupported menu (wrong RouterOS version or missing package) otherwise returns its parse
    # error as if it were data, which the model would try to interpret.
    if any(m in low for m in ("bad command name", "no such command", "expected end of command",
                              "syntax error", "no such item")):
        raise LiveError(
            f"'{query.key}' is not available on {device['slug']} "
            f"(RouterOS {device['ros_version'] or '?'}): {out.strip()[:120]}"
        )
    _cache[cache_key] = (now, out)
    return out


def filter_lines(text: str, match: str | None, limit: int, tail: bool) -> tuple[str, int, int]:
    """Filter and cap client-side; returns (text, shown, total)."""
    lines = [l for l in text.splitlines() if l.strip() and not _NOISE.match(l)]
    total = len(lines)
    if match:
        try:
            rx = re.compile(match, re.IGNORECASE)
        except re.error as exc:
            raise LiveError(f"invalid 'match' regex: {exc}") from exc
        lines = [l for l in lines if rx.search(l)]
    limit = max(1, min(int(limit or 50), MAX_LINES))
    shown = lines[-limit:] if tail else lines[:limit]
    return scrub.scrub("\n".join(shown))[0], len(shown), total


def clear_cache() -> None:
    _cache.clear()
