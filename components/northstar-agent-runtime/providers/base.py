"""Provider abstractions for the governed agent loop.

The loop never talks to a model API directly; it talks to a ``Provider``.
The wire format for ``messages`` is the Anthropic Messages shape so that the
``AnthropicProvider`` can pass it through unchanged while the offline
``ScriptedProvider`` simply ignores it.

The loop keeps no model credentials: an ``AnthropicProvider`` is constructed
by the host with an explicit client (or, by default, from the environment).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence, Union


class ProviderError(RuntimeError):
    """A provider call failed. The loop turns this into an event, not an exception."""


@dataclass(frozen=True)
class Usage:
    """Token accounting for one generation.

    ``input_tokens`` is the non-cached input. Cache reads and writes are
    reported separately because the API prices them differently.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_input_tokens": self.cache_read_input_tokens,
            "cache_creation_input_tokens": self.cache_creation_input_tokens,
        }

    @classmethod
    def zero(cls) -> "Usage":
        return cls()


@dataclass(frozen=True)
class TextBlock:
    text: str

    def to_wire(self) -> dict[str, Any]:
        return {"type": "text", "text": self.text}


@dataclass(frozen=True)
class ToolUseBlock:
    id: str
    name: str
    input: Mapping[str, Any]

    def to_wire(self) -> dict[str, Any]:
        return {"type": "tool_use", "id": self.id, "name": self.name, "input": dict(self.input)}


ContentBlock = Union[TextBlock, ToolUseBlock]


def text_blocks(content: Sequence[ContentBlock]) -> list[TextBlock]:
    return [b for b in content if isinstance(b, TextBlock)]


def tool_use_blocks(content: Sequence[ContentBlock]) -> list[ToolUseBlock]:
    return [b for b in content if isinstance(b, ToolUseBlock)]


@dataclass(frozen=True)
class ProviderRequest:
    """One model generation, in the Anthropic Messages wire shape."""

    model: str
    messages: tuple[dict[str, Any], ...]
    system: str = ""
    tools: tuple[dict[str, Any], ...] = ()
    max_tokens: int = 4096


@dataclass
class ProviderResponse:
    content: list[ContentBlock]
    usage: Usage = field(default_factory=Usage.zero)
    stop_reason: str = "end_turn"


class Provider:
    """Base class. Implementations must be safe to call repeatedly."""

    def create_message(self, request: ProviderRequest) -> ProviderResponse:
        raise NotImplementedError


# --- Message wire helpers (Anthropic Messages shape) -------------------------


def user_text_message(text: str) -> dict[str, Any]:
    return {"role": "user", "content": text}


def user_tool_result_message(results: list[dict[str, Any]]) -> dict[str, Any]:
    """A user message carrying one or more tool_result blocks.

    Each entry: ``{"tool_use_id": str, "content": str, "is_error": bool}``.
    Every block gets the ``type: "tool_result"`` field the API requires.
    """
    blocks = []
    for result in results:
        block = {
            "type": "tool_result",
            "tool_use_id": result["tool_use_id"],
            "content": result["content"],
            "is_error": bool(result.get("is_error", False)),
        }
        blocks.append(block)
    return {"role": "user", "content": blocks}


def assistant_wire_message(content: Sequence[ContentBlock]) -> dict[str, Any]:
    return {"role": "assistant", "content": [b.to_wire() for b in content]}
