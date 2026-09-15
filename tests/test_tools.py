from __future__ import annotations

import asyncio

from app import tools


def call(name, args):
    return asyncio.run(tools.call(name, args))


def test_search_rejects_bad_regex():
    assert call("search_config", {"pattern": "([unclosed"}).startswith("ERROR: invalid regex")


def test_unknown_tool_is_reported():
    assert call("nope", {}).startswith("ERROR: unknown tool")


def test_unknown_device_lists_known_ones():
    out = call("get_sections", {"device": "does-not-exist", "paths": ["/ip/address"]})
    assert out.startswith("ERROR: unknown device")


def test_bad_arguments_do_not_crash_the_chat():
    assert call("get_sections", {"device": "x", "nope": 1}).startswith("ERROR:")


EXPORT_WITH_LISTS = """\
/ip firewall address-list add list=Srv-list address=10.1.0.3
/ip firewall address-list add list=Srv-list address=10.1.0.14 disabled=yes
/ip firewall address-list add list=Other-list address=192.0.2.1
/interface list member add list=WAN interface=ether1
/ip firewall filter add action=drop chain=forward dst-address-list=Srv-list src-address=10.10.4.0/23
/ip firewall filter add action=accept chain=input in-interface-list=WAN src-address-list=!Admin-list
"""


def test_referenced_lists_are_appended_to_the_rules_that_name_them():
    blocks = tools.referenced_lists(EXPORT_WITH_LISTS,
                                    EXPORT_WITH_LISTS.splitlines()[4:],
                                    ["/ip/firewall/filter"])
    body = "\n".join(blocks)
    assert "list=Srv-list address=10.1.0.3" in body
    assert "list=Srv-list address=10.1.0.14 disabled=yes" in body   # a disabled member still matters
    assert "list=WAN interface=ether1" in body                      # interface lists too
    assert "Other-list" not in body                                 # unreferenced lists stay out


def test_a_long_list_does_not_crowd_out_a_short_one():
    bulk = "\n".join(f"/ip firewall address-list add list=Admin-list address=10.10.5.{i}"
                     for i in range(1, 200))
    text = bulk + "\n" + EXPORT_WITH_LISTS
    rules = ["/ip firewall filter add action=drop chain=forward dst-address-list=Srv-list",
             "/ip firewall filter add action=accept chain=input src-address-list=!Admin-list"]
    body = "\n".join(tools.referenced_lists(text, rules, ["/ip/firewall/filter"]))
    assert "list=Srv-list address=10.1.0.3" in body
    assert f"showing {tools.LIST_EXPANSION_MAX_LINES} of 199 entries" in body


def test_referenced_lists_skip_paths_the_caller_already_asked_for():
    asked = ["/ip/firewall/filter", "/ip/firewall/address-list"]
    blocks = tools.referenced_lists(EXPORT_WITH_LISTS, EXPORT_WITH_LISTS.splitlines()[4:], asked)
    assert not any("/ip/firewall/address-list" in b for b in blocks)


def test_schemas_match_registry():
    assert {s["name"] for s in tools.SCHEMAS} == set(tools.REGISTRY)
    for s in tools.SCHEMAS:
        assert s["description"] and s["parameters"]["type"] == "object"


def test_async_tools_are_registered_and_awaited():
    assert tools.ASYNC_TOOLS <= set(tools.REGISTRY)
    for name in tools.ASYNC_TOOLS:
        assert asyncio.iscoroutinefunction(tools.REGISTRY[name]), f"{name} listed async but is not"
    for name, fn in tools.REGISTRY.items():
        if name not in tools.ASYNC_TOOLS:
            assert not asyncio.iscoroutinefunction(fn), f"{name} is async but not in ASYNC_TOOLS"
