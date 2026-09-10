from __future__ import annotations

from typing import Any

import httpx

from ..pricing import Usage
from .base import LLMError, Provider, Reply, ToolCall


class AnthropicProvider(Provider):
    name = "anthropic"
    family = "anthropic"
    default_model = "claude-sonnet-5"


    def _url(self, path: str) -> str:
        return (self.base_url.rstrip("/") if self.base_url else "https://api.anthropic.com/v1") + path

    @staticmethod
    def _to_wire(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Anthropic carries tool results as user-role blocks, so consecutive ones are merged."""
        out: list[dict[str, Any]] = []
        for m in messages:
            if m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
            elif m["role"] == "assistant" and m.get("tool_calls"):
                blocks: list[dict[str, Any]] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                blocks += [{"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["arguments"]} for tc in m["tool_calls"]]
                out.append({"role": "assistant", "content": blocks})
            else:
                out.append({"role": m["role"], "content": m.get("content", "")})
        return out

    async def chat(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Reply:
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "system": system,
            "messages": self._to_wire(messages),
            "tools": [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools],
        }
        if not tools:
            payload.pop("tools")
        async with httpx.AsyncClient(timeout=180) as client:
            resp = await client.post(self._url("/messages"),
                                     headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}, json=payload)
        if resp.status_code != 200:
            raise LLMError(f"Anthropic {resp.status_code}: {resp.text[:400]}")
        data = resp.json()
        text, calls = "", []
        for block in data.get("content", []):
            if block["type"] == "text":
                text += block["text"]
            elif block["type"] == "tool_use":
                calls.append(ToolCall(block["id"], block["name"], block.get("input") or {}))
        u = data.get("usage") or {}
        # Anthropic reports cache reads/writes separately; input_tokens already excludes them.
        usage = Usage(
            uncached_input=int(u.get("input_tokens") or 0),
            cached_input=int(u.get("cache_read_input_tokens") or 0),
            cache_write=int(u.get("cache_creation_input_tokens") or 0),
            output=int(u.get("output_tokens") or 0),
        )
        return Reply(text, calls, usage, data.get("model", self.model))

    async def list_models(self) -> list[str]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(self._url("/models"),
                                    headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"})
        if resp.status_code != 200:
            raise LLMError(f"Anthropic {resp.status_code}: {resp.text[:200]}")
        return [m["id"] for m in resp.json().get("data", [])]
