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
