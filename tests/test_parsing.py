"""Parser / facts / scrubber tests. Run inside the image: docker compose run --rm --entrypoint pytest mikrotik-agent -q"""
from __future__ import annotations

from app import facts, rsc, scrub

# Addresses and MACs below are documentation ranges (RFC 5737 / RFC 7042), not real hosts.
EXPORT = """# 2026-09-10 10:55:57 by RouterOS 7.22.1
# software id = NMRU-A112
#
# model = C53UiG+5HPaxD2HPaxD
# serial number = HG909TCYXRC
/interface bridge add admin-mac=00:00:5E:00:53:01 auto-mac=no comment=defconf name=bridge
/interface vlan add interface=bridge name=vlan20 vlan-id=20
/interface wireguard add listen-port=13231 mtu=1420 name=wg0 private-key="SECRETKEY="
/interface wireguard peers add allowed-address=10.9.0.2/32 endpoint-address=203.0.113.7 endpoint-port=13231 interface=wg0 public-key="PUB="
/interface l2tp-client add connect-to=198.51.100.147 disabled=no name=l2tp-Home password=hunter2 use-ipsec=yes user=bob
/ip address add address=10.0.3.254/24 comment=defconf interface=bridge network=10.0.3.0
/ip address add address=192.168.2.254/24 interface=ether1 network=192.168.2.0
/ip dhcp-client add interface=ether1
/ip dhcp-server add address-pool=dhcp interface=bridge name=defconf
/ip firewall filter add action=accept chain=input comment="defconf: accept established" connection-state=established,related
/ip firewall filter add action=drop chain=input comment="defconf: drop all not coming from LAN" in-interface-list=!LAN
/ip firewall nat add action=masquerade chain=srcnat comment="defconf: masquerade" out-interface=ether1
/ip route add distance=1 gateway=192.168.2.1
/routing ospf instance add name=ospf1 router-id=10.0.3.254
/snmp community add addresses=0.0.0.0/0 name=public
/system identity set name=HSH-D
/ip service set [ find name=www ] disabled=yes
/ip service set [ find name=ssh ] port=22
"""


def test_strip_header_removes_volatile_banner():
    body = rsc.strip_header(EXPORT)
    assert body.startswith("/interface bridge add")
    assert "software id" not in body
    # Two exports differing only in the banner must be byte-identical after stripping.
    other = EXPORT.replace("10:55:57", "11:02:13")
    assert rsc.strip_header(other) == body


def test_parse_covers_every_command_line():
    body = rsc.strip_header(EXPORT)
    entries = rsc.parse(body)
    assert len(entries) == len([l for l in body.splitlines() if l.strip()])
    paths = {e.path for e in entries}
    assert "/ip/firewall/filter" in paths and "/interface/wireguard/peers" in paths


def test_parse_handles_quotes_and_selectors():
    e = rsc.parse('/ip firewall filter add action=drop chain=input comment="a, b=c"')[0]
    assert e.args["comment"] == "a, b=c" and e.args["action"] == "drop"
    sel = rsc.parse("/ip service set [ find name=www ] disabled=yes")[0]
    assert sel.selector == "find name=www" and sel.args["disabled"] == "yes"


def test_section_lines_prefix_and_exact():
    body = rsc.strip_header(EXPORT)
    assert len(rsc.section_lines(body, ["/ip firewall filter"])) == 2
    assert len(rsc.section_lines(body, ["/ip/firewall"])) == 3          # filter + nat
    assert len(rsc.section_lines(body, ["/interface/wireguard"])) == 2  # iface + peers


def test_facts_extract():
    f = facts.extract(rsc.strip_header(EXPORT))
    assert f["identity"] == "HSH-D"
    assert set(f["subnets"]) == {"10.0.3.0/24", "192.168.2.0/24"}
    assert f["wan_interfaces"] == ["ether1"]
    assert f["firewall"] == {"filter": 2, "nat": 1, "mangle": 0, "raw": 0, "address_lists": 0, "ipv6_filter": 0}
    assert f["routing"]["ospf"] is True
    assert [t["peer"] for t in f["tunnels"]] == ["203.0.113.7", "198.51.100.147"]
    assert [v["vlan_id"] for v in f["interfaces"]["vlan"]] == ["20"]
    assert {s["name"] for s in f["services"]} == {"ssh"}   # www is disabled


def test_scrub_hides_snmp_communities_when_quoted_indented_or_renamed():
    text = ("    /snmp community add name=corp-ro disabled=yes\n"
            "/snmp community set [ find default=yes ] addresses=10.0.0.0/8 name=corp-rw\n")
    out, counts = scrub.scrub(text)
    assert "corp-ro" not in out and "corp-rw" not in out
    assert counts["snmp-community"] == 2


def test_scrub_hides_secrets_but_keeps_structure():
    out, counts = scrub.scrub(EXPORT)
    assert "SECRETKEY=" not in out and "hunter2" not in out
    assert "name=\"<hidden>\"" in out                       # snmp community
    assert "public-key=\"PUB=\"" in out                     # public keys stay
    assert counts["private-key"] == 1 and counts["password"] == 1
    assert out.count("\n") == EXPORT.count("\n")


def test_summary_is_compact():
    body = rsc.strip_header(EXPORT)
    s = facts.summary({"slug": "hsh-d", "model": "hAP ax3", "ros_version": "7.22.1",
                       "site": "home", "role": "gw", "identity": "HSH-D", "status": "ok"},
                      facts.extract(body))
    assert "10.0.3.0/24" in s and "wireguard" in s and "ospf" in s
    assert len(s.splitlines()) <= 7
