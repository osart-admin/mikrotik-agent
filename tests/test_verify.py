"""Checking a plan marked as done against the configuration collected afterwards.

The cases are the ones from 415: plan #13 opened with `disable [find]` that left all 14 old
rules enabled, and plan #14's three `[find where ... comment=""]` lines matched nothing.
"""
from __future__ import annotations

from app import verify

BEFORE = """\
/ip firewall filter add action=accept chain=input src-address=77.88.224.93
/ip firewall filter add action=drop chain=input comment="defconf: drop invalid" connection-state=invalid
/ip firewall filter add action=drop chain=forward comment="defconf: drop invalid" connection-state=invalid
/ip firewall filter add action=accept chain=input src-address=10.0.10.0/24
/ip dns set allow-remote-requests=yes servers=8.8.8.8
"""


def statuses(commands, before, after):
    return [(c.status, c.note) for c in verify.check(commands, before, after)]


def test_an_added_rule_is_found_and_a_missing_one_is_not():
    after = BEFORE + '/ip firewall filter add action=drop chain=input comment="template: drop all other input"\n'
    got = statuses(['/ip firewall filter add action=drop chain=input comment="template: drop all other input"',
                    '/ip firewall filter add action=accept chain=input protocol=icmp place-before=0'], BEFORE, after)
    assert got[0][0] == "ok"
    assert got[1] == ("missing", "такой записи в конфигурации нет")


def test_re_adding_an_existing_rule_needs_a_second_copy():
    cmd = "/ip firewall filter add action=accept chain=input src-address=10.0.10.0/24"
    assert statuses([cmd], BEFORE, BEFORE)[0][0] == "missing"


def test_disable_by_comment_counts_every_matching_rule():
    after = BEFORE.replace('comment="defconf: drop invalid" connection-state=invalid',
                           'comment="defconf: drop invalid" connection-state=invalid disabled=yes')
    got = statuses(['/ip firewall filter disable [find where comment="defconf: drop invalid"]'], BEFORE, after)
    assert got == [("ok", "записей: 2")]


def test_a_disable_that_changed_nothing_is_reported():
    got = statuses(["/ip firewall filter disable [find]",
                    '/ip firewall filter disable [find where chain=input and src-address=77.88.224.93 and comment=""]'],
                   BEFORE, BEFORE)
    assert got == [("missing", "4 из 4 записей остались включены"), ("missing", "1 из 1 записей остались включены")]


def test_remove_and_set_through_find():
    after = BEFORE.replace("/ip firewall filter add action=accept chain=input src-address=77.88.224.93\n", "") \
                  .replace("src-address=10.0.10.0/24", "src-address=10.0.10.0/24 in-interface=wireguard")
    got = statuses(["/ip firewall filter remove [find where src-address=77.88.224.93]",
                    "/ip firewall filter set [find where src-address=10.0.10.0/24] in-interface=wireguard"],
                   BEFORE, after)
    assert [s for s, _ in got] == ["ok", "ok"]


def test_singleton_settings_are_checked_by_value():
    after = BEFORE.replace("servers=8.8.8.8", "servers=1.1.1.1")
    got = statuses(["/ip dns set servers=1.1.1.1", "/ip dns set servers=9.9.9.9", "/ip dns set cache-size=4096KiB"],
                   BEFORE, after)
    assert got[0][0] == "ok"
    assert got[1] == ("missing", "servers=1.1.1.1, а не 9.9.9.9")
    assert got[2][0] == "unknown"            # a default value is not in the export


def test_what_cannot_be_evaluated_is_not_guessed():
    got = statuses(["/ip firewall filter disable [find where src-address~\"77\"]",
                    "/ip firewall filter disable [find where comment=nothing-like-this]",
                    "/system note set note=x show-at-login=no"], BEFORE, BEFORE)
    assert [s for s, _ in got] == ["unknown", "unknown", "unknown"]


def test_conditions_parse_quoted_values_and_reject_other_operators():
    assert verify.conditions('find where chain=input and comment="a b"') == {"chain": "input", "comment": "a b"}
    assert verify.conditions("find default-name=ether2") == {"default-name": "ether2"}
    assert verify.conditions("find") == {}
    assert verify.conditions("find where a=1 or b=2") is None
    assert verify.conditions("3") is None
