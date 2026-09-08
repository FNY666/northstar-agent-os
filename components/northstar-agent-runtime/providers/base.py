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
from typing import Any, Iterable, Iterator, Literal, Sequence

# --------------------------------------------------------------------------
# Closed vocabularies
# --------------------------------------------------------------------------

#: ``postconditions`` is the verdict of the independent end-of-run check
#: (postconditions.py); it is a distinct subtype rather than ``informational`` so a
#: consumer can require it in a transcript without grepping text.
SystemSubtype = Literal["init", "compact_boundary", "informational", "postconditions"]

ResultSubtype = Literal[
    "success",
    "error_max_turns",
    "error_max_tool_calls",
    "error_max_budget_usd",
    "error_during_execution",
    "error_permission_denied",
    # The model stopped asking for tools, but the workspace does not say the work
    # happened: declared postconditions failed.
    "error_postconditions_failed",
    # The run never started: another live process holds the session transcript, and
    # appending to a file we do not own is the one thing that would make it unreadable.
    "error_session_busy",
]

RESULT_SUBTYPES: tuple[str, ...] = (
    "success",
    "error_max_turns",
    "error_max_tool_calls",
    "error_max_budget_usd",
    "error_during_execution",
    "error_permission_denied",
    "error_postconditions_failed",
    "error_session_busy",
)

SYSTEM_SUBTYPES: tuple[str, ...] = ("init", "compact_boundary", "informational", "postconditions")

BlockKind = Literal["text", "tool_use", "tool_result", "thinking"]

StopReason = Literal["end_turn", "tool_use", "max_tokens", "stop_sequence", "refusal"]


class ProviderError(RuntimeError):
    """Raised by a provider for any failure the loop should classify.

    Providers raise this; the loop converts it into an ``error_during_execution``
    result event. No other exception type may cross a provider boundary.
    """


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

    def __post_init__(self) -> None:
        if self.subtype not in RESULT_SUBTYPES:
            raise ValueError(f"ResultMessage.subtype must be one of {RESULT_SUBTYPES}")

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

    def snapshot(self) -> dict[str, Any]:
        """A redaction-safe description of the request for tracing/tests."""
        return {
            "model": self.model,
            "system_chars": len(self.system),
            "message_count": len(self.messages),
            "tool_names": [tool.get("name") for tool in self.tools],
            "turn_index": self.turn_index,
            "depth": self.depth,
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

    def text(self) -> str:
        """The turn's text as one string, in block order (what a stream must reproduce)."""
        return stream_comparable_text(self)


#: Per-chunk and per-turn ceilings on streamed text, enforced by the runtime rather
#: than trusted from the provider: a provider that emits one character per callback
#: must not be able to turn a turn's output into an unbounded event flood, and a
#: provider that never stops emitting must not be able to grow the event stream past
#: what a log shipper can carry.
MAX_STREAM_DELTA_CHARS = 2_000
MAX_STREAM_TURN_CHARS = 200_000


@dataclass(frozen=True)
class StreamDelta:
    """One provisional chunk of assistant text, on its way to becoming an :class:`AssistantMessage`.

    A delta is **display and observability only**. It is never written to the session
    transcript, never enters the model-visible context, and never authorises anything:
    the recorded fact is the assembled :class:`AssistantMessage` that follows it. That
    asymmetry is deliberate. A transcript digest or a checkpoint over token-sized chunks
    would certify a presentation detail, and a "did the run say X" question answered
    from a stream would be answered from the wrong artifact.

    Only ``text`` blocks are ever streamed. Tool input arrives as incremental JSON, and
    a half-received ``{"path": "/etc/pass`` is precisely the thing that must not be
    displayable, executable, or hashable - so partial tool arguments are not exposed as
    deltas at all, and neither is ``thinking`` (whose signature must be validated before
    the block is legitimate).
    """

    text: str
    block_index: int = 0
    turn_index: int = 0
    provider: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": "stream_delta",
            "text": self.text,
            "block_index": self.block_index,
            "turn_index": self.turn_index,
            "provider": self.provider,
        }


def split_for_stream(text: str, *, size: int = MAX_STREAM_DELTA_CHARS) -> list[str]:
    """Slice ``text`` into chunks no longer than ``size`` (the provider-side helper).

    Splitting on character count rather than on words or lines is on purpose: any
    boundary rule that depends on the *content* makes the chunking part of the model's
    output, and a provider must not get to decide what a turn's text looks like.
    """
    if size < 1:
        raise ValueError("size must be >= 1")
    if not text:
        return []
    return [text[start : start + size] for start in range(0, len(text), size)]


def stream_comparable_text(turn: Any) -> str:
    """The turn's text, joined **without** separators, for stream comparison.

    Distinct from :attr:`AssistantMessage.text`, which joins text blocks with newlines
    because a human reading a transcript should see them as paragraphs. A stream is
    compared block-wise and concatenatively: a provider that yields ``"a"`` then ``"b"``
    streamed exactly what it returned, and inventing a separator between the chunks to
    match the display join would make fidelity a function of formatting. Two definitions
    of "the same text" would guarantee a false alarm on the first multi-block answer.

    ``Generation`` content is not forced through :func:`coerce_blocks` at construction,
    because doing so would rewrite a provider's payload before the loop has decided to
    trust it; so anything reading text out of a raw Generation has to meet strings and
    dicts as well as block objects.
    """
    parts: list[str] = []
    for block in getattr(turn, "content", ()) or ():
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict):
            if block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        elif isinstance(block, TextBlock):
            parts.append(block.text)
    return "".join(parts)


def stream_fidelity(parts: Sequence[str], final_text: str) -> str | None:
    """Compare what a stream showed with what the run is about to record.

    Returns ``None`` when they agree, else a one-line description of the mismatch. The
    comparison target is the **assembled message**, not the provider's own object,
    because the artifact a later digest, checkpoint or reader consults is the record: if
    the two disagree about which text the turn contained, the record wins and the stream
    is the fault. The rule is strict in both directions - a provider may not show text
    the record does not contain (an unsupported claim about the model) and may not
    withhold text within the same turn (a stream that ends early is how a refusal gets
    hidden from someone watching live). The loop applies its own byte caps first, so a
    truncation caused by this client is not reported as a provider fault.
    """
    streamed = "".join(parts)
    final = final_text
    if streamed == final:
        return None
    if not streamed:
        return "the stream carried no text at all while the turn returned text"
    if final.startswith(streamed):
        return f"the stream stopped {len(final) - len(streamed)} char(s) short of the turn's text"
    if streamed.startswith(final):
        return f"the stream carried {len(streamed) - len(final)} char(s) the turn does not contain"
    shared = 0
    for left, right in zip(streamed, final):
        if left != right:
            break
        shared += 1
    return f"the stream and the turn diverge after {shared} char(s)"


class Provider:
    """Base class for providers; subclasses implement :meth:`generate`."""

    name: str = "base"

    #: Whether this provider reports text incrementally. It is a *capability claim*,
    #: checked by the runtime before ``stream=True`` is honoured, so a host that cannot
    #: stream fails with a configuration error instead of producing a run whose
    #: "streaming" arrives all at once - the kind of thing a demo quietly turns on and
    #: nobody re-checks. Setting it to ``True`` without overriding :meth:`stream` is
    #: caught too: see the loop's stream-fidelity check.
    streams: bool = False

    def generate(self, request: GenerationRequest) -> Generation:  # pragma: no cover - interface
        raise NotImplementedError("providers must implement generate()")

    def stream(self, request: GenerationRequest) -> "Iterator[StreamDelta | Generation]":
        """Yield :class:`StreamDelta` chunks, then exactly one :class:`Generation`.

        The default offers no chunks and returns the whole turn, which is the safe shape
        for a *direct* caller: an embedder that always iterates ``stream()`` never has to
        branch on capability. It is **not** what ``streams = True`` entitles a run to see -
        the loop treats "a text turn, no chunks" as a broken promise, because a provider
        could otherwise advertise streaming, show nothing, and still pass every check.
        """
        yield self.generate(request)

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
    "RESULT_SUBTYPES",
    "SYSTEM_SUBTYPES",
    "ResultMessage",
    "ResultSubtype",
    "MAX_STREAM_DELTA_CHARS",
    "MAX_STREAM_TURN_CHARS",
    "StopReason",
    "StreamDelta",
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
    "split_for_stream",
    "stream_comparable_text",
    "stream_fidelity",
    "transcript_to_api",
]


def _unused(_: Sequence[Any]) -> None:  # keep linters honest about imports
    return None
