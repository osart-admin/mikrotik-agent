from __future__ import annotations

from .anthropic_provider import AnthropicProvider
from .base import LLMError, Provider, Reply, ToolCall
from .openai_provider import OpenAIProvider

PROVIDERS: dict[str, type[Provider]] = {"openai": OpenAIProvider, "anthropic": AnthropicProvider}


def build(provider: str, api_key: str, model: str = "", base_url: str = "") -> Provider:
    cls = PROVIDERS.get(provider)
    if cls is None:
        raise LLMError(f"unknown provider '{provider}'")
    return cls(api_key, model, base_url)


__all__ = ["PROVIDERS", "build", "LLMError", "Provider", "Reply", "ToolCall", "OpenAIProvider", "AnthropicProvider"]
