from __future__ import annotations

from .anthropic_provider import AnthropicProvider
from .base import LLMError, Provider, Reply, ToolCall
from .openai_provider import OpenAIProvider
from .openai_responses import OpenAIResponsesProvider

# "openai" is the Responses API: it is the only OpenAI endpoint that accepts function tools
# together with reasoning. "openai-chat" stays available for OpenAI-compatible proxies that only
# implement /v1/chat/completions.
PROVIDERS: dict[str, type[Provider]] = {
    "openai": OpenAIResponsesProvider,
    "openai-chat": OpenAIProvider,
    "anthropic": AnthropicProvider,
}

PROVIDER_LABELS = {
    "openai": "OpenAI — Responses API (рекомендуется)",
    "openai-chat": "OpenAI-совместимый — Chat Completions",
    "anthropic": "Anthropic",
}


def build(provider: str, api_key: str, model: str = "", base_url: str = "", reasoning_effort: str = "") -> Provider:
    cls = PROVIDERS.get(provider)
    if cls is None:
        raise LLMError(f"unknown provider '{provider}'")
    return cls(api_key, model, base_url, reasoning_effort)


def family(provider: str) -> str:
    cls = PROVIDERS.get(provider)
    return cls.family if cls else provider


__all__ = ["PROVIDERS", "PROVIDER_LABELS", "build", "family", "LLMError", "Provider", "Reply",
           "ToolCall", "OpenAIProvider", "OpenAIResponsesProvider", "AnthropicProvider"]
