"""Deterministic facts from a parsed export: what the fleet map and the UI table are built from.

Nothing here is LLM-driven. It is intentionally tolerant - an unknown menu just isn't counted.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from .rsc import Entry, parse

_TUNNEL_CLIENTS = {
    "/interface/l2tp-client": "l2tp-client",
    "/interface/pptp-client": "pptp-client",
    "/interface/sstp-client": "sstp-client",
    "/interface/ovpn-client": "ovpn-client",
    "/interface/eoip": "eoip",
    "/interface/gre": "gre",
    "/interface/ipip": "ipip",
    "/interface/6to4": "6to4",
    "/interface/vxlan": "vxlan",
}
_VPN_SERVERS = {
    "/interface/l2tp-server/server": "l2tp-server",
    "/interface/pptp-server/server": "pptp-server",
    "/interface/sstp-server/server": "sstp-server",
    "/interface/ovpn-server/server": "ovpn-server",
    "/ip/ipsec/peer": None,  # handled separately (peers are both client and server side)
}


def _network(addr: str) -> str | None:
    try:
        return str(ipaddress.ip_interface(addr).network)
    except ValueError:
        return None


def extract(text: str) -> dict[str, Any]:
    entries = parse(text)
    f: dict[str, Any] = {
        "identity": "",
        "interfaces": {"ethernet": [], "bridge": [], "vlan": [], "bonding": [], "wireguard": [], "pppoe_client": [], "wifi": []},
        "addresses": [],
        "subnets": [],
        "dhcp_servers": [],
        "dhcp_client_interfaces": [],
        "dns_servers": [],
        "firewall": {"filter": 0, "nat": 0, "mangle": 0, "raw": 0, "address_lists": 0, "ipv6_filter": 0},
        "nat_out_interfaces": [],
        "routes": {"static": 0, "default_gateways": []},
        "routing": {"ospf": False, "bgp": False, "rip": False, "vrfs": 0},
        "tunnels": [],
        "vpn_servers": [],
        "services": [],
        "snmp": False,
        "ntp_servers": [],
        "capsman": False,
        "hotspot": False,
        "container": False,
        "counts": {"lines": len(entries), "users": 0, "scripts": 0, "schedulers": 0, "queues": 0},
        "sections": {},
    }
    ifs = f["interfaces"]
    seen_subnets: set[str] = set()

    for e in entries:
        f["sections"][e.path] = f["sections"].get(e.path, 0) + 1
        p, a = e.path, e.args

        if p == "/system/identity":
            f["identity"] = a.get("name", "")
        elif p == "/interface/ethernet" and e.verb == "set":
            ifs["ethernet"].append({"name": e.name, "default": re.sub(r".*default-name=", "", e.selector) or e.name, "disabled": e.is_disabled(), "comment": a.get("comment", "")})
        elif p == "/interface/bridge" and e.verb == "add":
            ifs["bridge"].append({"name": e.name, "vlan_filtering": a.get("vlan-filtering") == "yes"})
        elif p == "/interface/vlan" and e.verb == "add":
            ifs["vlan"].append({"name": e.name, "vlan_id": a.get("vlan-id", ""), "interface": a.get("interface", ""), "disabled": e.is_disabled()})
        elif p == "/interface/bonding" and e.verb == "add":
            ifs["bonding"].append({"name": e.name, "slaves": a.get("slaves", ""), "mode": a.get("mode", "")})
        elif p == "/interface/wireguard" and e.verb == "add":
            ifs["wireguard"].append({"name": e.name, "listen_port": a.get("listen-port", ""), "disabled": e.is_disabled()})
        elif p == "/interface/wireguard/peers" and e.verb == "add":
            f["tunnels"].append({"type": "wireguard-peer", "interface": a.get("interface", ""), "peer": a.get("endpoint-address", ""), "port": a.get("endpoint-port", ""), "allowed": a.get("allowed-address", ""), "comment": a.get("comment") or a.get("name", ""), "disabled": e.is_disabled()})
        elif p == "/interface/pppoe-client" and e.verb == "add":
            ifs["pppoe_client"].append({"name": e.name, "interface": a.get("interface", ""), "disabled": e.is_disabled()})
        elif p in ("/interface/wifi", "/interface/wireless") and e.verb in ("add", "set"):
            ssid = a.get("ssid") or a.get("configuration.ssid") or a.get(".ssid", "")
            band = a.get("band") or a.get("channel.band") or a.get(".band", "")
            if ssid or e.verb == "set":
                ifs["wifi"].append({"name": e.name, "ssid": ssid, "band": band, "disabled": e.is_disabled()})
        elif p in _TUNNEL_CLIENTS and e.verb == "add":
            f["tunnels"].append({"type": _TUNNEL_CLIENTS[p], "interface": e.name, "peer": a.get("connect-to") or a.get("remote-address", ""), "comment": a.get("comment", ""), "disabled": e.is_disabled()})
        elif p in _VPN_SERVERS and _VPN_SERVERS[p] and a.get("enabled") == "yes":
            f["vpn_servers"].append(_VPN_SERVERS[p])
        elif p == "/ip/ipsec/peer" and e.verb == "add":
            f["tunnels"].append({"type": "ipsec-peer", "interface": e.name, "peer": a.get("address", ""), "passive": a.get("passive") == "yes", "comment": a.get("comment", ""), "disabled": e.is_disabled()})
        elif p == "/ip/address" and e.verb == "add":
            addr = a.get("address", "")
            f["addresses"].append({"address": addr, "interface": a.get("interface", ""), "comment": a.get("comment", ""), "disabled": e.is_disabled()})
            net = _network(addr)
            if net and net not in seen_subnets and not e.is_disabled():
                seen_subnets.add(net)
                f["subnets"].append(net)
        elif p == "/ip/dhcp-server" and e.verb == "add":
            f["dhcp_servers"].append({"name": e.name, "interface": a.get("interface", ""), "pool": a.get("address-pool", ""), "disabled": e.is_disabled()})
        elif p == "/ip/dhcp-client" and e.verb == "add":
            f["dhcp_client_interfaces"].append(a.get("interface", ""))
        elif p == "/ip/dns" and e.verb == "set":
            f["dns_servers"] = [s for s in a.get("servers", "").split(",") if s]
        elif p == "/ip/firewall/filter" and e.verb == "add":
            f["firewall"]["filter"] += 1
        elif p == "/ip/firewall/nat" and e.verb == "add":
            f["firewall"]["nat"] += 1
            if a.get("action") == "masquerade" and a.get("out-interface") and a["out-interface"] not in f["nat_out_interfaces"]:
                f["nat_out_interfaces"].append(a["out-interface"])
            if a.get("action") == "masquerade" and a.get("out-interface-list") and a["out-interface-list"] not in f["nat_out_interfaces"]:
                f["nat_out_interfaces"].append("list:" + a["out-interface-list"])
        elif p == "/ip/firewall/mangle" and e.verb == "add":
            f["firewall"]["mangle"] += 1
        elif p == "/ip/firewall/raw" and e.verb == "add":
            f["firewall"]["raw"] += 1
        elif p == "/ip/firewall/address-list" and e.verb == "add":
            f["firewall"]["address_lists"] += 1
        elif p == "/ipv6/firewall/filter" and e.verb == "add":
            f["firewall"]["ipv6_filter"] += 1
        elif p == "/ip/route" and e.verb == "add":
            f["routes"]["static"] += 1
            if a.get("dst-address", "0.0.0.0/0") in ("0.0.0.0/0", "") and a.get("gateway"):
                f["routes"]["default_gateways"].append(a["gateway"])
        elif p.startswith("/routing/ospf"):
            f["routing"]["ospf"] = True
        elif p.startswith("/routing/bgp"):
            f["routing"]["bgp"] = True
        elif p.startswith("/routing/rip"):
            f["routing"]["rip"] = True
        elif p in ("/ip/vrf", "/routing/table") and e.verb == "add":
            f["routing"]["vrfs"] += 1
        elif p == "/ip/service" and e.verb == "set":
            svc = e.name or e.selector.replace("find name=", "")
            if svc and not e.is_disabled():
                f["services"].append({"name": svc, "port": a.get("port", ""), "address": a.get("address", "")})
        elif p == "/snmp" and e.verb == "set" and a.get("enabled") == "yes":
            f["snmp"] = True
        elif p == "/system/ntp/client/servers" and e.verb == "add":
            f["ntp_servers"].append(a.get("address", ""))
        elif p == "/system/ntp/client" and e.verb == "set" and a.get("servers"):
            f["ntp_servers"] = a["servers"].split(",")
        elif p.startswith("/caps-man") or p.startswith("/interface/wifi/capsman"):
            f["capsman"] = True
        elif p.startswith("/ip/hotspot") and e.verb == "add":
            f["hotspot"] = True
        elif p.startswith("/container") and e.verb == "add":
            f["container"] = True
        elif p == "/user" and e.verb == "add":
            f["counts"]["users"] += 1
        elif p == "/system/script" and e.verb == "add":
            f["counts"]["scripts"] += 1
        elif p == "/system/scheduler" and e.verb == "add":
            f["counts"]["schedulers"] += 1
        elif p in ("/queue/simple", "/queue/tree") and e.verb == "add":
            f["counts"]["queues"] += 1

    # Which ethernet ports carry a WAN role: DHCP client, PPPoE, or masquerade out-interface.
    wan = set(f["dhcp_client_interfaces"]) | {c["interface"] for c in ifs["pppoe_client"]} | {o for o in f["nat_out_interfaces"] if not o.startswith("list:")}
    f["wan_interfaces"] = sorted(w for w in wan if w)
    return f


def to_json(facts: dict[str, Any]) -> str:
    return json.dumps(facts, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def summary(device: dict[str, Any], facts: dict[str, Any] | None) -> str:
    """Compact multi-line block for one device - the unit of the fleet map in the system prompt."""
    head = f"{device['slug']} | {device.get('model') or device.get('board') or '?'}, ROS {device.get('ros_version') or '?'} | site={device.get('site') or '-'} role={device.get('role') or '-'}"
    if device.get("identity") and device["identity"] != device["slug"]:
        head += f" | identity={device['identity']}"
    if device.get("status") != "ok":
        head += f" | STATUS={device.get('status')}"
    if not facts:
        return head + "\n  (no config collected yet)"
    ifs = facts["interfaces"]
    lines = [head]
    wan = ", ".join(facts.get("wan_interfaces") or []) or "-"
    vlans = ", ".join(f"{v['name']}({v['vlan_id']})" for v in ifs["vlan"][:12]) or "-"
    bridges = ", ".join(b["name"] for b in ifs["bridge"]) or "-"
    lines.append(f"  WAN: {wan} | bridges: {bridges} | VLANs: {vlans}")
    lines.append(f"  subnets: {', '.join(facts['subnets'][:16]) or '-'}")
    tun = [f"{t['type']}:{t.get('interface') or ''}->{t['peer'] or '?'}" + (" (disabled)" if t.get("disabled") else "") for t in facts["tunnels"][:12]]
    if ifs["wireguard"]:
        tun = [f"wireguard:{w['name']}:{w['listen_port']}" for w in ifs["wireguard"]] + tun
    srv = list(facts["vpn_servers"])
    lines.append(f"  tunnels: {', '.join(tun) or '-'} | vpn servers: {', '.join(srv) or '-'}")
    r = facts["routing"]
    proto = ", ".join(k for k in ("ospf", "bgp", "rip") if r.get(k)) or "static only"
    fw = facts["firewall"]
    lines.append(f"  routing: {proto}, {facts['routes']['static']} static, gw {', '.join(facts['routes']['default_gateways'][:3]) or '-'} | fw: {fw['filter']} filter, {fw['nat']} nat, {fw['mangle']} mangle")
    extras = []
    if ifs["wifi"]:
        extras.append("wifi: " + ", ".join(f"{w['name']}={w['ssid']}" for w in ifs["wifi"] if w["ssid"])[:120])
    if facts["dhcp_servers"]:
        extras.append("dhcp: " + ", ".join(d["name"] for d in facts["dhcp_servers"]))
    for flag in ("capsman", "hotspot", "snmp", "container"):
        if facts.get(flag):
            extras.append(flag)
    if extras:
        lines.append("  " + " | ".join(extras))
    return "\n".join(lines)
