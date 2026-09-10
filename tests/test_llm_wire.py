"""Wire-format tests for the provider adapters (no network).

The Responses API is not optional here: /v1/chat/completions rejects function tools together
with reasoning_effort, which is exactly this agent's normal mode.
"""
from __future__ import annotations

import json

from app import llm
from app.llm.openai_provider import OpenAIProvider
from app.llm.openai_responses import OpenAIResponsesProvider

SCHEMA = [{"name": "search_config", "description": "grep", "parameters": {"type": "object", "properties": {}}}]
HISTORY = [
    {"role": "user", "content": "как настроен pptp?"},
    {"role": "assistant", "content": "", "tool_calls": [{"id": "call_1", "name": "search_config", "arguments": {"pattern": "pptp"}}],
     "raw": [{"type": "reasoning", "id": "rs_1", "encrypted_content": "OPAQUE"},
             {"type": "function_call", "call_id": "call_1", "name": "search_config", "arguments": "{\"pattern\": \"pptp\"}"}]},
    {"role": "tool", "tool_call_id": "call_1", "content": "/interface pptp-client add ..."},
]


def test_default_openai_provider_is_the_responses_api():
    assert llm.PROVIDERS["openai"] is OpenAIResponsesProvider
    assert llm.PROVIDERS["openai"].supports_reasoning_with_tools is True
    assert llm.PROVIDERS["openai-chat"].supports_reasoning_with_tools is False
    assert llm.family("openai") == llm.family("openai-chat") == "openai"


def test_responses_sends_tools_and_reasoning_together():
    """The whole reason this adapter exists: Chat Completions rejects this combination."""
    p = OpenAIResponsesProvider("k", "gpt-5.6-terra", reasoning_effort="high")
    payload = p.build_payload("sys", HISTORY, SCHEMA)
    assert payload["reasoning"] == {"effort": "high"}
    assert payload["tools"][0]["name"] == "search_config"     # flat, not nested under "function"
    assert "function" not in payload["tools"][0]
    assert payload["include"] == ["reasoning.encrypted_content"]
    assert payload["store"] is False


def test_responses_input_replays_reasoning_items_verbatim():
    items = OpenAIResponsesProvider._to_input(HISTORY)
    kinds = [i.get("type") or i.get("role") for i in items]
    assert kinds == ["user", "reasoning", "function_call", "function_call_output"]
    assert items[1]["encrypted_content"] == "OPAQUE"
    assert items[3]["call_id"] == "call_1"


def test_responses_input_without_raw_items_still_builds_the_call():
    history = [dict(HISTORY[1])]
    history[0].pop("raw")
    items = OpenAIResponsesProvider._to_input(history)
    assert items[0]["type"] == "function_call"
    assert json.loads(items[0]["arguments"]) == {"pattern": "pptp"}


def test_responses_usage_splits_cached_input():
    u = OpenAIResponsesProvider._usage({"usage": {
        "input_tokens": 12_000, "input_tokens_details": {"cached_tokens": 10_000},
        "output_tokens": 900, "output_tokens_details": {"reasoning_tokens": 700}}})
    assert u.uncached_input == 2_000 and u.cached_input == 10_000
    assert u.total_input == 12_000 and u.reasoning == 700


def test_chat_completions_forces_reasoning_none_when_tools_are_present():
    """Current models reason by default, so omitting the parameter is not enough - it must be
    sent as "none" or the endpoint rejects function tools outright."""
    p = OpenAIProvider("k", "gpt-5.6-terra", reasoning_effort="high")
    with_tools = p.build_payload("sys", [{"role": "user", "content": "hi"}], SCHEMA)
    assert with_tools["reasoning_effort"] == "none"
    without = p.build_payload("sys", [{"role": "user", "content": "hi"}], [])
    assert without["reasoning_effort"] == "high" and "tools" not in without


def test_chat_completions_tool_schema_is_nested():
    wire = OpenAIProvider._to_wire([{"role": "assistant", "content": "",
                                     "tool_calls": [{"id": "c1", "name": "x", "arguments": {"a": 1}}]}])
    assert wire[0]["tool_calls"][0]["type"] == "function"
    assert wire[0]["tool_calls"][0]["function"]["name"] == "x"


def test_configs_are_not_stored_on_the_provider():
    """store:false keeps router configuration out of OpenAI-side conversation storage."""
    p = OpenAIResponsesProvider("k", "gpt-5.6-terra")
    assert p.build_payload("sys", HISTORY, SCHEMA)["store"] is False
