"""Live-state queries.

The security property under test: a command sent to a router is always a literal constant from
the whitelist. Nothing the model emits is ever interpolated into it.
"""
from __future__ import annotations

import asyncio

import pytest

from app import live, tools


def test_commands_are_literal_constants():
    for q in live.QUERIES.values():
        assert "{" not in q.command and "}" not in q.command, f"{q.key} command has a placeholder"
        assert "%" not in q.command and "+" not in q.command
        assert q.command.startswith("/")


def test_every_command_is_a_read():
    """The agent's group grants ssh,read - no writes, and nothing needing the 'test' policy."""
    forbidden = ("ping", "traceroute", "bandwidth-test", "scan", "sniff", "torch", "flood",
                 " add ", " set ", " remove ", "reboot", "reset")
    for q in live.QUERIES.values():
        low = q.command.lower()
        assert "print" in low or "monitor" in low, f"{q.key} is not a print/monitor"
        for word in forbidden:
            assert word not in low, f"{q.key} uses {word!r}, which needs more than 'read'"


def test_unknown_query_is_rejected_before_any_connection():
    async def go():
        return await tools.call("get_live_state", {"device": "nope", "query": "'; /system reboot"})
    out = asyncio.run(go())
    assert out.startswith("ERROR:")
    assert "reboot" not in live.QUERIES


def test_missing_query_lists_the_valid_keys():
    out = asyncio.run(tools.call("get_live_state", {"device": "x"}))
    assert "ERROR:" in out and "dhcp_leases" in out


def test_filter_happens_locally_and_caps_output():
    text = "\n".join(f"line {i} wireless" if i % 2 else f"line {i} dhcp" for i in range(300))
    body, shown, total = live.filter_lines(text, "wireless", 10, tail=False)
    assert total == 300 and shown == 10
    assert all("wireless" in l for l in body.splitlines())


def test_tail_returns_the_newest_lines_for_logs():
    text = "\n".join(str(i) for i in range(100))
    body, shown, _ = live.filter_lines(text, None, 5, tail=True)
    assert body.splitlines() == ["95", "96", "97", "98", "99"]
    body2, _, _ = live.filter_lines(text, None, 5, tail=False)
    assert body2.splitlines() == ["0", "1", "2", "3", "4"]


def test_limit_is_clamped():
    text = "\n".join(str(i) for i in range(1000))
    _, shown, _ = live.filter_lines(text, None, 99999, tail=False)
    assert shown == live.MAX_LINES


def test_bad_filter_regex_is_reported():
    with pytest.raises(live.LiveError):
        live.filter_lines("a\nb", "([unclosed", 10, tail=False)


def test_output_is_scrubbed():
    text = '/ppp active add name=u password=hunter2 service=l2tp'
    body, _, _ = live.filter_lines(text, None, 10, tail=False)
    assert "hunter2" not in body and "<hidden>" in body


def test_tool_schema_enumerates_the_whitelist():
    schema = next(s for s in tools.SCHEMAS if s["name"] == "get_live_state")
    assert set(schema["parameters"]["properties"]["query"]["enum"]) == set(live.QUERIES)
    assert "get_live_state" in tools.ASYNC_TOOLS


def test_routeros_header_noise_is_dropped():
    """`print terse` still emits a flags legend and column header; they are not data."""
    raw = ("Flags: X - DISABLED\n"
           "Columns: CHAIN, ACTION, BYTES, PACKETS\n"
           "#   CHAIN    ACTION  BYTES  PACKETS\n"
           " 0 chain=input action=accept bytes=100 packets=2\n"
           " 1 chain=input action=drop bytes=5 packets=1\n")
    body, shown, total = live.filter_lines(raw, None, 50, tail=False)
    assert total == 2 and shown == 2
    assert "Flags:" not in body and "Columns:" not in body
    assert body.splitlines()[0].startswith(" 0 chain=input")


def test_log_lines_are_not_mistaken_for_headers():
    raw = "2026-09-10 23:36:26 wireless,info DE:14:40:72:BA:74@wifi1(HSH) disconnected\n"
    body, shown, _ = live.filter_lines(raw, None, 10, tail=True)
    assert shown == 1 and "wireless,info" in body


def test_only_the_log_needs_a_policy_beyond_read():
    """Verified on RouterOS 7.22: /log print is refused with ssh,read; everything else works."""
    needing = {q.key: q.needs for q in live.QUERIES.values() if q.needs}
    assert needing == {"log": "test"}


def test_describe_warns_about_the_extra_policy():
    text = live.describe()
    assert "requires the 'test' policy" in text
    assert text.count("requires the") == 1


def test_unsupported_menu_is_an_error_not_data():
    """RouterOS answers an unknown menu with a parse error the model would otherwise read as data."""
    import asyncio
    from types import SimpleNamespace

    device = {"id": -1, "slug": "x", "host": "h", "port": 22, "enabled": 1,
              "username": "agent", "ros_version": "7.22.1", "auth": "key"}

    async def fake_run(self, command, timeout=30):
        return "bad command name wireless (line 1 column 12)"

    async def go():
        import app.live as mod
        real = mod.RouterSSH
        class Fake:
            def __init__(self, *a, **k): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            run = fake_run
        mod.RouterSSH = Fake
        try:
            await mod.fetch(device, "wifi_clients_legacy")
        finally:
            mod.RouterSSH = real
            mod.clear_cache()

    with pytest.raises(live.LiveError, match="not available"):
        asyncio.run(go())
