from __future__ import annotations

from app import tools


def test_search_rejects_bad_regex():
    assert tools.call("search_config", {"pattern": "([unclosed"}).startswith("ERROR: invalid regex")


def test_unknown_tool_is_reported():
    assert tools.call("nope", {}).startswith("ERROR: unknown tool")


def test_unknown_device_lists_known_ones():
    out = tools.call("get_sections", {"device": "does-not-exist", "paths": ["/ip/address"]})
    assert out.startswith("ERROR: unknown device")


def test_schemas_match_registry():
    assert {s["name"] for s in tools.SCHEMAS} == set(tools.REGISTRY)
    for s in tools.SCHEMAS:
        assert s["description"] and s["parameters"]["type"] == "object"
