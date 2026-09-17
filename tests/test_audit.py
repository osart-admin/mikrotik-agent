from __future__ import annotations

from datetime import date

from app import audit, rsc


def findings(text, dates=None, today=date(2026, 9, 15)):
    return audit.audit(text, dates or {}, today)


def test_rule_matching_an_empty_list_can_never_fire():
    text = """\
/ip firewall address-list add list=Srv-list address=10.1.0.3 disabled=yes
/ip firewall filter add action=drop chain=forward dst-address-list=Srv-list
"""
    f = findings(text)
    assert [x.check for x in f] == ["dangling-list"]
    assert f[0].severity == "medium"
    assert "все записи списка «Srv-list» (1 шт.) отключены" in f[0].detail


def test_a_negated_empty_list_widens_the_rule_instead():
    text = """\
/ip firewall filter add action=drop chain=input src-address-list=!Admin-list
"""
    f = findings(text)
    assert f[0].severity == "high"          # nothing is excluded, so the drop hits everyone
    assert "списка «Admin-list» нет в конфиге" in f[0].detail


def test_the_list_a_rule_writes_into_is_not_a_dangling_reference():
    text = """\
/ip firewall filter add action=add-src-to-address-list address-list=Scanners chain=input
"""
    assert findings(text) == []


def test_ipv6_rules_are_checked_against_ipv6_lists():
    text = """\
/ipv6 firewall address-list add address=::1/128 list=no_forward_ipv6
/ip firewall address-list add address=10.0.0.1 list=v4only
/ipv6 firewall filter add action=drop chain=forward src-address-list=no_forward_ipv6
/ipv6 firewall filter add action=drop chain=input src-address-list=!v4only
"""
    f = findings(text)
    assert [(x.line_no, x.severity) for x in f] == [(4, "high")]
    assert "списка «v4only» нет в конфиге" in f[0].detail


def test_lists_filled_at_runtime_are_not_dangling():
    text = """\
/ip firewall filter add action=add-src-to-address-list address-list=Scanners chain=input protocol=tcp
/ip firewall filter add action=drop chain=input src-address-list=Scanners
/ppp profile add address-list=vpn-clients interface-list=vpn-ifaces name=vpn
/ip dhcp-server add address-lists=guests,iot interface=bridge name=dhcp1
/ip firewall filter add action=accept chain=forward src-address-list=vpn-clients in-interface-list=vpn-ifaces
/ip firewall filter add action=drop chain=forward src-address-list=iot
"""
    assert [x for x in findings(text) if x.check == "dangling-list"] == []


def test_a_disabled_filler_does_not_fill_the_list():
    text = """\
/ip firewall filter add action=add-src-to-address-list address-list=Scanners chain=input disabled=yes
/ip firewall filter add action=drop chain=forward src-address-list=Scanners
"""
    assert [x.line_no for x in findings(text) if x.check == "dangling-list"] == [2]


def test_builtin_and_included_interface_lists_are_not_dangling():
    text = """\
/interface list add name=LAN
/interface list add include=LAN name=ALL-LOCAL
/interface list member add interface=bridge list=LAN
/ip firewall filter add action=drop chain=input in-interface-list=!all
/ip firewall filter add action=accept chain=input in-interface-list=ALL-LOCAL
/interface bridge filter add action=drop chain=forward in-interface-list=dynamic
/ip firewall filter add action=drop chain=input in-interface-list=WAN
"""
    assert [x.line_no for x in findings(text) if x.check == "dangling-list"] == [7]


def test_a_list_named_outside_a_rule_table_is_not_a_reference():
    text = "/ip neighbor discovery-settings set discover-interface-list=MGMT\n" \
           "/ppp profile add interface-list=MGMT name=p\n"
    assert findings(text) == []


def test_a_disabled_rule_is_not_reported_for_its_own_references():
    text = """\
/ip firewall filter add action=drop chain=forward dst-address-list=Gone disabled=yes
"""
    assert [x.check for x in findings(text)] == []


def test_a_broader_earlier_rule_shadows_the_narrow_ones_after_it():
    text = """\
/ip firewall filter add action=accept chain=forward dst-address=10.1.0.0/24
/ip firewall filter add action=accept chain=forward dst-address=10.1.0.0/24 src-address=10.10.4.0/23
/ip firewall filter add action=accept chain=forward dst-address=10.1.0.0/24 src-address=10.8.1.0/24
"""
    f = [x for x in findings(text) if x.check == "shadowed-rules"]
    assert len(f) == 1
    assert f[0].line_no == 1
    assert "перекрывает 2 правила ниже" in f[0].detail


def test_a_catch_all_rule_is_reported_as_high():
    text = """\
/ip firewall filter add action=drop chain=forward
/ip firewall filter add action=accept chain=forward src-address=10.0.0.0/8
"""
    f = [x for x in findings(text) if x.check == "shadowed-rules"]
    assert f[0].severity == "high"
    assert "перекрывает 1 правило ниже" in f[0].detail


def test_rules_in_another_chain_are_not_shadowed():
    text = """\
/ip firewall filter add action=accept chain=forward dst-address=10.1.0.0/24
/ip firewall filter add action=accept chain=input dst-address=10.1.0.0/24 src-address=10.10.4.0/23
"""
    assert [x for x in findings(text) if x.check == "shadowed-rules"] == []


def test_a_narrower_earlier_rule_shadows_nothing():
    text = """\
/ip firewall filter add action=accept chain=forward dst-address=10.1.0.0/24 protocol=tcp
/ip firewall filter add action=accept chain=forward dst-address=10.1.0.0/24
"""
    assert [x for x in findings(text) if x.check == "shadowed-rules"] == []


def test_disabled_entries_are_reported_by_age_and_by_comment():
    text = """\
/ip firewall address-list add list=Srv-list address=10.1.0.9 disabled=yes
/ip firewall address-list add list=Srv-list address=10.1.0.8 comment="udalit" disabled=yes
/ip firewall address-list add list=Srv-list address=10.1.0.7 disabled=yes
"""
    dates = {1: "2026-01-01", 2: "2026-09-14", 3: "2026-09-14"}
    f = {x.line_no: x for x in findings(text, dates) if x.check == "stale-disabled"}
    assert set(f) == {1, 2}          # line 3 is recent and unremarkable
    assert f[1].severity == "low" and "257 дн." in f[1].detail
    assert f[2].severity == "medium" and "«udalit»" in f[2].detail


def test_an_undated_disabled_entry_is_only_reported_when_the_comment_says_so():
    text = """\
/ip firewall address-list add list=X address=10.0.0.1 disabled=yes
/ip firewall address-list add list=X address=10.0.0.2 comment="test 2" disabled=yes
"""
    f = [x for x in findings(text) if x.check == "stale-disabled"]
    assert [x.line_no for x in f] == [2]


def test_temporary_words_only_count_at_the_start_of_a_word():
    comments = {
        "latest backup route": False, "Threshold": False, "golden image": False,
        "template": False, "temperature sensor": False, "удалённый доступ": False,
        "testing": True, "TMP": True, "old-gw": True, "gw_old": True, "временно": True,
        "удалить после 01.10": True, "udal": True,
    }
    for comment, junk in comments.items():
        text = f'/ip route add gateway=10.0.0.1 comment="{comment}" disabled=yes\n'
        assert bool(findings(text)) is junk, comment


def test_blame_skips_lines_that_are_not_committed_yet():
    from app import store

    store.write_device("blamed", "/ip address add address=10.0.0.1/24\n", "{}")
    store.commit("blame test")
    store.write_device("blamed", "/ip address add address=10.0.0.1/24\n/ip address add address=10.0.0.2/24\n", "{}")
    dates = store.blame_dates("blamed")
    store.remove_device("blamed")
    store.commit("blame test cleanup")
    assert list(dates) == [1]
    assert store.first_commit_date() <= store.history(limit=1)[0]["date"]


def test_findings_come_back_worst_first():
    text = """\
/ip firewall filter add action=drop chain=forward
/ip firewall filter add action=accept chain=forward src-address=10.0.0.0/8
/ip firewall address-list add list=X address=10.0.0.2 comment="tmp" disabled=yes
"""
    assert [x.severity for x in findings(text)] == ["high", "medium"]


def test_plural_agreement():
    assert [audit._plural(n, "правило", "правила", "правил") for n in (1, 2, 5, 11, 21, 104)] == [
        "правило", "правила", "правил", "правил", "правило", "правила"]


def test_entries_keep_their_export_line_numbers():
    text = "\n" * 40 + "/ip firewall filter add action=drop chain=forward dst-address-list=Gone\n"
    assert rsc.parse(text)[0].line_no == 41
    assert findings(text)[0].line_no == 41
