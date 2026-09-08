"""Message and provider vocabulary shared by every Northstar runtime module.

This module is deliberately dependency-free: the runtime must stay importable
on a host that has neither ``anthropic`` nor OpenTelemetry installed.

Type-alias note (this bit us once): every closed set of strings below is a
``typing.Literal[...]``, never a ``"a" | "b"`` expression. A string-union alias
is evaluated at runtime and raises ``TypeError`` the moment anyone touches it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Literal, Sequence

# --------------------------------------------------------------------------
# Closed vocabularies
# --------------------------------------------------------------------------

SystemSubtype = Literal["init", "compact_boundary", "informational"]

ResultSubtype = Literal[
    "success",
    "error_max_turns",
    "error_max_tool_calls",
    "error_max_budget_usd",
    "error_during_execution",
    "error_permission_denied",
    "error_cancelled",
]

RESULT_SUBTYPES: tuple[str, ...] = (
    "success",
    "error_max_turns",
    "error_max_tool_calls",
    "error_max_budget_usd",
    "error_during_execution",
    "error_permission_denied",
    "error_cancelled",
)

SYSTEM_SUBTYPES: tuple[str, ...] = ("init", "compact_boundary", "informational")

BlockKind = Literal["text", "tool_use", "tool_result", "thinking"]

StopReason = Literal["end_turn", "tool_use", "max_tokens", "stop_sequence", "refusal"]


class ProviderError(RuntimeError):
    """Raised by a provider for any failure the loop should classify.

    Providers raise this; the loop converts it into an ``error_during_execution``
    result event. No other exception type may cross a provider boundary.

    ``error_code`` is deliberately small and provider-neutral. The loop uses it
    to distinguish a recoverable context-window overflow from an ordinary
    outage, authentication failure, or rate limit; it must never retry the
    latter merely because an exception happened to contain the word "context".
    """

    error_code = "provider_error"
    retryable = False


class ContextOverflowError(ProviderError):
    """The provider rejected the request because its input context was too large."""

    error_code = "context_overflow"
    retryable = True


def is_context_overflow(error: BaseException) -> bool:
    """Return whether a provider error is explicitly classified as overflow.

    Provider adapters should raise :class:`ContextOverflowError`, while custom
    providers may expose the same two attributes on their own ``ProviderError``
    subclass. This helper keeps the loop independent of a concrete SDK.
    """

    return getattr(error, "error_code", "") == "context_overflow"


# --------------------------------------------------------------------------
# Usage
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Usage:
    """Token counts in the shape the Anthropic Messages API reports them.

    ``input_tokens`` excludes cached tokens: ``cache_read_input_tokens`` and
    ``cache_creation_input_tokens`` are billed at their own multipliers, so the
    three fields must never be collapsed into one number.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0

    def __post_init__(self) -> None:
        for name in (
            "input_tokens",
            "output_tokens",
            "cache_read_input_tokens",
            "cache_creation_input_tokens",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"Usage.{name} must be an int, got {type(value).__name__}")
            if value < 0:
                raise ValueError(f"Usage.{name} must not be negative")

    @property
    def total_tokens(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_read_input_tokens
            + self.cache_creation_input_tokens
        )

    @property
    def billable_input_tokens(self) -> int:
        return (
            self.input_tokens
            + self.cache_read_input_tokens
            + self.cache_creation_input_tokens
        )

    def __add__(self, other: "Usage | None") -> "Usage":
        if other is None:
            return self
        if not isinstance(other, Usage):
            return self
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_input_tokens=self.cache_read_input_tokens + other.cache_read_input_tokens,
            cache_creation_input_tokens=self.cache_creation_input_tokens
            + other.cache_creation_input_tokens,
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_input_tokens": self.cache_read_input_tokens,
            "cache_creation_input_tokens": self.cache_creation_input_tokens,
        }

    @classmethod
    def from_mapping(cls, value: Any) -> "Usage":
        if isinstance(value, Usage):
            return value
        if not isinstance(value, dict):
            return cls()

        def number(key: str) -> int:
            raw = value.get(key, 0)
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                return 0
            return max(0, int(raw))

        return cls(
            input_tokens=number("input_tokens"),
            output_tokens=number("output_tokens"),
            cache_read_input_tokens=number("cache_read_input_tokens"),
            cache_creation_input_tokens=number("cache_creation_input_tokens"),
        )


ZERO_USAGE = Usage()


# --------------------------------------------------------------------------
# Content blocks
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TextBlock:
    text: str = ""
    kind: BlockKind = "text"

    def to_api(self) -> dict[str, Any]:
        return {"type": "text", "text": self.text}

    def render(self) -> str:
        return self.text


@dataclass(frozen=True)
class ThinkingBlock:
    text: str = ""
    signature: str = ""
    kind: BlockKind = "thinking"

    def to_api(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"type": "thinking", "thinking": self.text}
        if self.signature:
            payload["signature"] = self.signature
        return payload

    def render(self) -> str:
        return ""


@dataclass(frozen=True)
class ToolUseBlock:
    id: str = ""
    name: str = ""
    input: dict[str, Any] = field(default_factory=dict)
    kind: BlockKind = "tool_use"

    def to_api(self) -> dict[str, Any]:
        return {"type": "tool_use", "id": self.id, "name": self.name, "input": dict(self.input)}

    def render(self) -> str:
        return f"[tool_use {self.name} {json.dumps(self.input, ensure_ascii=False, sort_keys=True, default=str)[:400]}]"


@dataclass(frozen=True)
class ToolResultBlock:
    tool_use_id: str = ""
    content: Any = ""
    is_error: bool = False
    kind: BlockKind = "tool_result"

    def to_api(self) -> dict[str, Any]:
        return {
            "type": "tool_result",
            "tool_use_id": self.tool_use_id,
            "content": _normalise_result_content(self.content),
            "is_error": bool(self.is_error),
        }

    def render(self) -> str:
        return _flatten_result_content(self.content)

    def text(self) -> str:
        return _flatten_result_content(self.content)


AnyBlock = Any  # one of TextBlock | ThinkingBlock | ToolUseBlock | ToolResultBlock


def _normalise_result_content(value: Any) -> Any:
    """Return an API-legal tool_result payload (string or list of blocks)."""
    if isinstance(value, (list, tuple)):
        blocks: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, TextBlock):
                blocks.append(item.to_api())
            elif isinstance(item, dict) and item.get("type") == "text":
                blocks.append({"type": "text", "text": str(item.get("text", ""))})
            else:
                blocks.append({"type": "text", "text": _stringify(item)})
        return blocks
    if isinstance(value, dict):
        return [{"type": "text", "text": json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)}]
    return _stringify(value)


def flatten_result_content(value: Any) -> str:
    """Plain-text view of a tool_result payload (str, blocks, or a dict)."""
    return _flatten_result_content(value)


def _flatten_result_content(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        parts: list[str] = []
        for item in value:
            if isinstance(item, TextBlock):
                parts.append(item.text)
            elif isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            else:
                parts.append(_stringify(item))
        return "\n".join(parts)
    return _stringify(value)


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(value)


# --------------------------------------------------------------------------
# Event types
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SystemMessage:
    """Runtime chatter: run setup, compaction boundaries, host notices."""

    subtype: SystemSubtype = "informational"
    content: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    role: Literal["system"] = "system"

    def __post_init__(self) -> None:
        if self.subtype not in SYSTEM_SUBTYPES:
            raise ValueError(f"SystemMessage.subtype must be one of {SYSTEM_SUBTYPES}")

    def to_api(self) -> dict[str, Any] | None:
        # Only a compact boundary carries model-visible context.
        if self.subtype == "compact_boundary" and self.content:
            return {"role": "user", "content": [{"type": "text", "text": COMPACT_HEADER + self.content}]}
        if self.subtype == "informational" and self.content:
            return {"role": "user", "content": [{"type": "text", "text": CONTEXT_HEADER + self.content}]}
        return None

    def render(self) -> str:
        return f"[system:{self.subtype}] {self.content}"


COMPACT_HEADER = "[Earlier conversation summary]\n"
CONTEXT_HEADER = "[Host context]\n"


@dataclass(frozen=True)
class AssistantMessage:
    content: tuple[Any, ...] = ()
    model: str = ""
    usage: Usage = ZERO_USAGE
    stop_reason: str = ""
    message_id: str = ""
    role: Literal["assistant"] = "assistant"

    def __post_init__(self) -> None:
        # Host code writes AssistantMessage(content="hi") as often as
        # AssistantMessage(content=(TextBlock("hi"),)); both must survive the trip
        # to the API, so the content is normalised here rather than at each call site.
        object.__setattr__(self, "content", _coerce_content(self.content))

    @property
    def tool_uses(self) -> tuple[ToolUseBlock, ...]:
        return tuple(block for block in self.content if isinstance(block, ToolUseBlock))

    @property
    def text(self) -> str:
        return "\n".join(block.text for block in self.content if isinstance(block, TextBlock) and block.text)

    def to_api(self) -> dict[str, Any]:
        blocks = [block.to_api() for block in self.content]
        if not blocks:
            blocks = [{"type": "text", "text": ""}]
        return {"role": "assistant", "content": blocks}

    def render(self) -> str:
        return " ".join(block.render() for block in self.content if block.render()).strip()


@dataclass(frozen=True)
class UserMessage:
    """A user turn, or the tool_result carrier for a batch of tool calls."""

    content: tuple[Any, ...] = ()
    is_meta: bool = False
    meta_reason: str = ""
    role: Literal["user"] = "user"

    def __post_init__(self) -> None:
        object.__setattr__(self, "content", _coerce_content(self.content))

    @staticmethod
    def text_block(text: str, *, is_meta: bool = False, meta_reason: str = "") -> "UserMessage":
        return UserMessage(content=(TextBlock(text=text),), is_meta=is_meta, meta_reason=meta_reason)

    @property
    def text(self) -> str:
        return "\n".join(block.text for block in self.content if isinstance(block, TextBlock) and block.text)

    @property
    def tool_results(self) -> tuple[ToolResultBlock, ...]:
        return tuple(block for block in self.content if isinstance(block, ToolResultBlock))

    def to_api(self) -> dict[str, Any]:
        blocks = [block.to_api() for block in self.content]
        if not blocks:
            blocks = [{"type": "text", "text": ""}]
        return {"role": "user", "content": blocks}

    def render(self) -> str:
        return " ".join(block.render() for block in self.content if block.render()).strip()


@dataclass(frozen=True)
class ResultMessage:
    """Exactly one per run. Any expected failure is this event, never an exception."""

    subtype: ResultSubtype = "success"
    num_turns: int = 0
    duration_ms: int = 0
    total_cost_usd: float = 0.0
    total_usage: Usage = ZERO_USAGE
    session_id: str = ""
    pricing_estimated: bool = False
    errors: tuple[str, ...] = ()
    permission_denials: tuple[dict[str, Any], ...] = ()
    stop_reason: str = ""
    role: Literal["result"] = "result"
    # Continuity metadata is part of the terminal report, not just an internal
    # boundary event, so CLI/SDK consumers can account for rollover without
    # replaying the whole transcript.
    context_windows: int = 1
    context_overflow_retries: int = 0

    def __post_init__(self) -> None:
        if self.subtype not in RESULT_SUBTYPES:
            raise ValueError(f"ResultMessage.subtype must be one of {RESULT_SUBTYPES}")
        if isinstance(self.context_windows, bool) or not isinstance(self.context_windows, int) or self.context_windows < 1:
            raise ValueError("ResultMessage.context_windows must be a positive integer")
        if isinstance(self.context_overflow_retries, bool) or not isinstance(self.context_overflow_retries, int) or self.context_overflow_retries < 0:
            raise ValueError("ResultMessage.context_overflow_retries must be a non-negative integer")

    @property
    def is_error(self) -> bool:
        """Derived, never supplied: every non-success subtype is an error."""
        return self.subtype != "success"

    def to_api(self) -> dict[str, Any] | None:
        return None

    def render(self) -> str:
        return f"[result:{self.subtype}] turns={self.num_turns} cost=${self.total_cost_usd:.6f}"


Message = Any  # SystemMessage | AssistantMessage | UserMessage | ResultMessage

TRANSCRIPT_TYPES = (SystemMessage, AssistantMessage, UserMessage)


# --------------------------------------------------------------------------
# Transcript serialisation
# --------------------------------------------------------------------------


def transcript_to_api(messages: Iterable[Message]) -> list[dict[str, Any]]:
    """Render a transcript as an Anthropic ``messages`` payload.

    Two API constraints shape this function:

    1. Roles must alternate, so consecutive same-role events are merged into a
       single message with concatenated blocks. Host-injected informational and
       compact-boundary messages would otherwise break the request.
    2. The payload must start with a ``user`` turn.
    """
    rendered: list[dict[str, Any]] = []
    for message in messages:
        if isinstance(message, ResultMessage):
            continue
        if isinstance(message, SystemMessage) and message.subtype == "init":
            continue
        api = message.to_api()
        if api is None:
            continue
        if rendered and rendered[-1]["role"] == api["role"]:
            previous = rendered[-1]["content"]
            current = api["content"]
            rendered[-1]["content"] = previous + current
        else:
            rendered.append(api)
    if not rendered:
        rendered = [{"role": "user", "content": [{"type": "text", "text": "(no context)"}]}]
    if rendered[0]["role"] == "assistant":
        rendered.insert(0, {"role": "user", "content": [{"type": "text", "text": "(continued session)"}]})
    return rendered


def estimate_transcript_tokens(messages: Sequence[Message] | Sequence[dict[str, Any]]) -> int:
    """Deterministic token estimate; used for compaction triggers, never billing.

    Billing always comes from provider-reported usage. This estimate only decides
    when to compact, so a rough number is acceptable and keeps the runtime
    testable without a tokenizer dependency.
    """
    payload = []
    for message in messages:
        if isinstance(message, dict):
            payload.append(message)
        else:
            api = message.to_api()
            if api is not None:
                payload.append(api)
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return max(1, len(text) // 4)


# --------------------------------------------------------------------------
# Provider interface
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolSpecPayload:
    """The wire shape a provider needs to describe a tool."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)

    def to_api(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema or {"type": "object", "properties": {}},
        }


@dataclass(frozen=True)
class GenerationRequest:
    system: str
    messages: tuple[dict[str, Any], ...]
    tools: tuple[dict[str, Any], ...] = ()
    model: str = ""
    max_tokens: int = 4096
    stop_sequences: tuple[str, ...] = ()
    agent: str = ""
    turn_index: int = 0
    depth: int = 0
    # Optional host-side limit forwarded for provider diagnostics. The runtime
    # performs the preflight itself; providers must not rely on this field to
    # enforce safety.
    context_window_tokens: int | None = None

    def snapshot(self) -> dict[str, Any]:
        """A redaction-safe description of the request for tracing/tests."""
        return {
            "model": self.model,
            "system_chars": len(self.system),
            "message_count": len(self.messages),
            "tool_names": [tool.get("name") for tool in self.tools],
            "turn_index": self.turn_index,
            "depth": self.depth,
            "context_window_tokens": self.context_window_tokens,
        }


@dataclass(frozen=True)
class Generation:
    """One provider turn."""

    content: tuple[Any, ...] = ()
    usage: Usage = ZERO_USAGE
    stop_reason: str = "end_turn"
    model: str = ""

    @property
    def tool_uses(self) -> tuple[ToolUseBlock, ...]:
        return tuple(block for block in self.content if isinstance(block, ToolUseBlock))


class Provider:
    """Base class for providers; subclasses implement :meth:`generate`."""

    name: str = "base"
    # Optional model/provider hint. RuntimeConfig.context_window_tokens takes
    # precedence; a hint is useful for embedded providers that know their model
    # limit without making the runtime depend on an SDK's model catalogue.
    context_window_tokens: int | None = None

    def generate(self, request: GenerationRequest) -> Generation:  # pragma: no cover - interface
        raise NotImplementedError("providers must implement generate()")

    def close(self) -> None:
        return None


def _coerce_content(content: Any) -> tuple[Any, ...]:
    if isinstance(content, str):
        content = (content,)
    if content and isinstance(content, (list, tuple)) and all(isinstance(item, (TextBlock, ToolUseBlock, ToolResultBlock, ThinkingBlock)) for item in content):
        return tuple(content)
    return coerce_blocks(content)


def coerce_blocks(values: Iterable[Any] | None) -> tuple[Any, ...]:
    """Accept blocks, dicts, or plain strings and return provider blocks."""
    blocks: list[Any] = []
    for value in values or ():
        if isinstance(value, (TextBlock, ToolUseBlock, ToolResultBlock, ThinkingBlock)):
            blocks.append(value)
        elif isinstance(value, str):
            blocks.append(TextBlock(text=value))
        elif isinstance(value, dict):
            kind = value.get("type")
            if kind == "text":
                blocks.append(TextBlock(text=str(value.get("text", ""))))
            elif kind == "thinking":
                blocks.append(ThinkingBlock(text=str(value.get("thinking", value.get("text", "")))))
            elif kind == "tool_use":
                raw_input = value.get("input", {})
                blocks.append(
                    ToolUseBlock(
                        id=str(value.get("id", "")),
                        name=str(value.get("name", "")),
                        input=dict(raw_input) if isinstance(raw_input, dict) else {"value": raw_input},
                    )
                )
            elif kind == "tool_result":
                blocks.append(
                    ToolResultBlock(
                        tool_use_id=str(value.get("tool_use_id", "")),
                        content=value.get("content", ""),
                        is_error=bool(value.get("is_error", False)),
                    )
                )
            else:
                blocks.append(TextBlock(text=_stringify(value)))
        else:
            blocks.append(TextBlock(text=_stringify(value)))
    return tuple(blocks)


def render_transcript(messages: Sequence[Message]) -> str:
    """Human-readable transcript for CLI output and subagent reports."""
    lines: list[str] = []
    for message in messages:
        rendered = message.render() if isinstance(message, (SystemMessage, AssistantMessage, UserMessage)) else ""
        if rendered:
            lines.append(rendered)
    return "\n".join(lines)


__all__ = [
    "AnyBlock",
    "AssistantMessage",
    "BlockKind",
    "COMPACT_HEADER",
    "CONTEXT_HEADER",
    "Generation",
    "GenerationRequest",
    "Message",
    "Provider",
    "ProviderError",
    "ContextOverflowError",
    "is_context_overflow",
    "RESULT_SUBTYPES",
    "SYSTEM_SUBTYPES",
    "ResultMessage",
    "ResultSubtype",
    "StopReason",
    "SystemMessage",
    "SystemSubtype",
    "ThinkingBlock",
    "ToolResultBlock",
    "ToolSpecPayload",
    "ToolUseBlock",
    "TRANSCRIPT_TYPES",
    "Usage",
    "UserMessage",
    "ZERO_USAGE",
    "coerce_blocks",
    "estimate_transcript_tokens",
    "flatten_result_content",
    "render_transcript",
    "transcript_to_api",
]


def _unused(_: Sequence[Any]) -> None:  # keep linters honest about imports
    return None
