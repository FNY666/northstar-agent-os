"""Northstar runtime provider package."""
from __future__ import annotations

from providers.base import (
    AssistantMessage,
    Generation,
    GenerationRequest,
    Provider,
    ProviderError,
    ResultMessage,
    SystemMessage,
    Usage,
    UserMessage,
)

__all__ = [
    "AssistantMessage",
    "Generation",
    "GenerationRequest",
    "Provider",
    "ProviderError",
    "ResultMessage",
    "SystemMessage",
    "Usage",
    "UserMessage",
    "make_provider",
]


def make_provider(kind: str = "scripted", **kwargs):
    """Factory used by the CLI; keeps ``anthropic`` importable only on demand."""
    if kind == "scripted":
        from providers.scripted import ScriptedProvider

        return ScriptedProvider(**kwargs)
    if kind == "anthropic":
        from providers.anthropic import AnthropicProvider

        return AnthropicProvider(**kwargs)
    raise ValueError(f"unknown provider kind: {kind!r}")
