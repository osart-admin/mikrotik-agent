"""OpenAI Responses API (/v1/responses).

Required rather than optional for this app: /v1/chat/completions rejects function tools combined
with reasoning_effort ("Function tools with reasoning_effort are not supported ... use
/v1/responses"), and a tool-calling agent that may not reason is the wrong trade-off here.

Two details that matter:
- ``store: false`` keeps router configurations off OpenAI's servers. The cost is that reasoning
  state is not kept for us between calls, so ``include: reasoning.encrypted_content`` is
  requested and the opaque reasoning items are echoed back on the next call of the same turn.
  Dropping them makes the model re-derive its plan after every tool result.
- Tool schemas are flat here (``{"type": "function", "name": ...}``), not nested under a
  ``function`` key as in Chat Completions.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from ..pricing import Usage
from .base import LLMError, Provider, Reply, ToolCall


class OpenAIResponsesProvider(Provider):
    name = "openai"
    family = "openai"
    default_model = "gpt-5.6-terra"
    supports_reasoning_with_tools = True

    def _url(self, path: str) -> str:
        return (self.base_url.rstrip("/") if self.base_url else "https://api.openai.com/v1") + path

    @staticmethod
    def _to_input(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for m in messages:
            role = m["role"]
            if role == "user":
                items.append({"role": "user", "content": [{"type": "input_text", "text": m.get("content", "")}]})
            elif role == "assistant":
                # Replay the provider's own output items verbatim when we captured them: they
                # carry the reasoning blocks that make the next call coherent.
                raw = m.get("raw")
                if raw:
                    items.extend(raw)
                    continue
                if m.get("content"):
                    items.append({"role": "assistant", "content": [{"type": "output_text", "text": m["content"]}]})
                for tc in m.get("tool_calls") or []:
                    items.append({"type": "function_call", "call_id": tc["id"], "name": tc["name"],
                                  "arguments": json.dumps(tc["arguments"], ensure_ascii=False)})
            elif role == "tool":
                items.append({"type": "function_call_output", "call_id": m["tool_call_id"],
                              "output": m.get("content", "")})
        return items

    @staticmethod
    def _usage(data: dict[str, Any]) -> Usage:
        u = data.get("usage") or {}
        total_in = int(u.get("input_tokens") or 0)
        cached = int((u.get("input_tokens_details") or {}).get("cached_tokens") or 0)
        return Usage(
            uncached_input=max(0, total_in - cached),
            cached_input=cached,
            cache_write=0,
            output=int(u.get("output_tokens") or 0),
            reasoning=int((u.get("output_tokens_details") or {}).get("reasoning_tokens") or 0),
        )

    def build_payload(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "instructions": system,
            "input": self._to_input(messages),
            "store": False,
        }
        if tools:
            payload["tools"] = [
                {"type": "function", "name": t["name"], "description": t["description"], "parameters": t["parameters"]}
                for t in tools
            ]
        if self.reasoning_effort:
            payload["reasoning"] = {"effort": self.reasoning_effort}
            payload["include"] = ["reasoning.encrypted_content"]
        return payload

    async def chat(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Reply:
        payload = self.build_payload(system, messages, tools)
        async with httpx.AsyncClient(timeout=600) as client:
            resp = await client.post(self._url("/responses"),
                                     headers={"Authorization": f"Bearer {self.api_key}"}, json=payload)
        if resp.status_code != 200:
            raise LLMError(f"OpenAI {resp.status_code}: {resp.text[:500]}")
        data = resp.json()
        if data.get("error"):
            raise LLMError(f"OpenAI: {json.dumps(data['error'], ensure_ascii=False)[:400]}")

        text, calls, raw = "", [], []
        for item in data.get("output", []):
            kind = item.get("type")
            if kind == "message":
                for block in item.get("content", []):
                    if block.get("type") == "output_text":
                        text += block.get("text", "")
                raw.append(item)
            elif kind == "function_call":
                try:
                    args = json.loads(item.get("arguments") or "{}")
                except json.JSONDecodeError as exc:
                    raise LLMError(f"model returned invalid tool arguments for {item.get('name')}: {exc}") from exc
                calls.append(ToolCall(item.get("call_id") or item.get("id", ""), item.get("name", ""), args))
                raw.append(item)
            elif kind == "reasoning":
                raw.append(item)

        reply = Reply(text, calls, self._usage(data), data.get("model", self.model))
        reply.raw_items = raw
        return reply

    async def list_models(self) -> list[str]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(self._url("/models"), headers={"Authorization": f"Bearer {self.api_key}"})
        if resp.status_code != 200:
            raise LLMError(f"OpenAI {resp.status_code}: {resp.text[:200]}")
        return sorted(m["id"] for m in resp.json().get("data", []) if m.get("id", "").startswith(("gpt-", "o")))
