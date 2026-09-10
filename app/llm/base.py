"""Provider-neutral chat interface.

A turn is a list of dicts: {"role": user|assistant|tool, "content": str,
"tool_calls": [{"id","name","arguments"}], "tool_call_id": str}. Each provider adapter
translates that to and from its own wire format so agent.py stays vendor-free.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..pricing import Usage


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class Reply:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    model: str = ""


class LLMError(Exception):
    pass


class Provider:
    name = "base"
    default_model = ""

    def __init__(self, api_key: str, model: str = "", base_url: str = "", reasoning_effort: str = ""):
        self.api_key = api_key
        self.model = model or self.default_model
        self.base_url = base_url
        self.reasoning_effort = reasoning_effort

    async def chat(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Reply:
        raise NotImplementedError

    async def list_models(self) -> list[str]:
        return []
