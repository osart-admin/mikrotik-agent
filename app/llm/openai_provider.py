from __future__ import annotations

import json
from typing import Any

import httpx

from ..pricing import Usage
from .base import LLMError, Provider, Reply, ToolCall


class OpenAIProvider(Provider):
    name = "openai"
    default_model = "gpt-5.6-terra"

    def _url(self, path: str) -> str:
        return (self.base_url.rstrip("/") if self.base_url else "https://api.openai.com/v1") + path

    @staticmethod
    def _to_wire(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for m in messages:
            if m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
            elif m["role"] == "assistant" and m.get("tool_calls"):
                out.append({
                    "role": "assistant",
                    "content": m.get("content") or None,
                    "tool_calls": [
                        {"id": tc["id"], "type": "function",
                         "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"], ensure_ascii=False)}}
                        for tc in m["tool_calls"]
                    ],
                })
            else:
                out.append({"role": m["role"], "content": m.get("content", "")})
        return out

    @staticmethod
    def _usage(data: dict[str, Any]) -> Usage:
        """Normalise OpenAI usage.

        ``prompt_tokens`` already includes cached tokens, so the uncached figure is the
        difference - otherwise cached input would be billed twice, at both rates.
        """
        u = data.get("usage") or {}
        prompt = int(u.get("prompt_tokens") or 0)
        details = u.get("prompt_tokens_details") or {}
        cached = int(details.get("cached_tokens") or 0)
        # Field name for billable cache writes is not stable across model families; try the
        # known spellings and fall back to 0 rather than guessing a cost.
        written = int(details.get("cache_write_tokens") or details.get("cache_creation_tokens") or 0)
        out_details = u.get("completion_tokens_details") or {}
        return Usage(
            uncached_input=max(0, prompt - cached - written),
            cached_input=cached,
            cache_write=written,
            output=int(u.get("completion_tokens") or 0),
            reasoning=int(out_details.get("reasoning_tokens") or 0),
        )

    async def chat(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Reply:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *self._to_wire(messages)],
        }
        if tools:
            payload["tools"] = [{"type": "function", "function": t} for t in tools]
        if self.reasoning_effort:
            payload["reasoning_effort"] = self.reasoning_effort
        async with httpx.AsyncClient(timeout=300) as client:
            resp = await client.post(self._url("/chat/completions"),
                                     headers={"Authorization": f"Bearer {self.api_key}"}, json=payload)
        if resp.status_code != 200:
            raise LLMError(f"OpenAI {resp.status_code}: {resp.text[:400]}")
        data = resp.json()
        choice = data["choices"][0]["message"]
        calls = [
            ToolCall(c["id"], c["function"]["name"], json.loads(c["function"].get("arguments") or "{}"))
            for c in (choice.get("tool_calls") or [])
        ]
        return Reply(choice.get("content") or "", calls, self._usage(data), data.get("model", self.model))

    async def list_models(self) -> list[str]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(self._url("/models"), headers={"Authorization": f"Bearer {self.api_key}"})
        if resp.status_code != 200:
            raise LLMError(f"OpenAI {resp.status_code}: {resp.text[:200]}")
        return sorted(m["id"] for m in resp.json().get("data", []) if m.get("id", "").startswith(("gpt-", "o1", "o3", "o4")))
