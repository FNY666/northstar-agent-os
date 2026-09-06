"""Deterministic, offline provider used by every Northstar runtime test.

ScriptedProvider is not a mock of convenience: it is the reference provider for
the whole component. Tests assert loop behaviour against it, so its semantics
are part of the runtime contract:

* turns are consumed in order, one :meth:`generate` call per turn;
* usage numbers are reported per turn so budget accounting is testable;
* running the script dry raises :class:`ProviderError`, which makes an
  off-by-one in turn accounting a loud failure instead of a silent pass;
* it records every request so tests can assert what the model was shown.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from providers.base import (
    Generation,
    GenerationRequest,
    Provider,
    ProviderError,
    Usage,
    coerce_blocks,
)


@dataclass(frozen=True)
class ScriptedTurn:
    """One scripted model turn."""

    blocks: tuple[Any, ...] = ()
    usage: Usage = field(default_factory=Usage)
    stop_reason: str = "end_turn"
    raises: Exception | None = None

    @staticmethod
    def text(text: str, *, usage: Usage | dict[str, Any] | None = None, model: str = "scripted") -> "ScriptedTurn":
        return ScriptedTurn(blocks=(text,), usage=_usage(usage), stop_reason="end_turn")

    @staticmethod
    def tool(
        name: str,
        payload: dict[str, Any] | None = None,
        *,
        call_id: str | None = None,
        also_text: str = "",
        usage: Usage | dict[str, Any] | None = None,
    ) -> "ScriptedTurn":
        blocks: list[Any] = []
        if also_text:
            blocks.append(also_text)
        call = {"type": "tool_use", "name": name, "input": dict(payload or {})}
        if call_id:
            call["id"] = call_id
        blocks.append(call)
        return ScriptedTurn(blocks=tuple(blocks), usage=_usage(usage), stop_reason="tool_use")

    @staticmethod
    def tools(calls: Sequence[Any], *, usage: Usage | dict[str, Any] | None = None) -> "ScriptedTurn":
        return ScriptedTurn(blocks=tuple(calls), usage=_usage(usage), stop_reason="tool_use")

    @staticmethod
    def error(error: Exception) -> "ScriptedTurn":
        return ScriptedTurn(blocks=(), raises=error)


def _usage(value: Usage | dict[str, Any] | None) -> Usage:
    if value is None:
        return Usage()
    return Usage.from_mapping(value)


def _coerce(turn: Any) -> ScriptedTurn:
    """Accept the many shapes a test may write, and produce one ScriptedTurn.

    Recognised: a ScriptedTurn, a Generation, a bare string, a dict with
    ``blocks``/``content``, a ``{"text": ...}`` or ``{"tool": {...}}`` shorthand,
    a sequence of blocks, and ``{"raises": exc}`` on its own or with any of them.
    """
    if isinstance(turn, ScriptedTurn):
        return turn
    if isinstance(turn, Generation):
        return ScriptedTurn(blocks=turn.content, usage=turn.usage, stop_reason=turn.stop_reason)
    if isinstance(turn, str):
        return ScriptedTurn(blocks=(turn,))
    if isinstance(turn, dict):
        payload = dict(turn)
        raises = payload.pop("raises", None)
        usage = _usage(payload.pop("usage", None))
        stop_reason = str(payload.pop("stop_reason", "") or "")
        also_text = payload.pop("also_text", None)
        blocks: list[Any] = []
        if "blocks" in payload or "content" in payload:
            blocks = list(coerce_blocks(payload.get("blocks") or payload.get("content") or ()))
        elif "text" in payload:
            blocks = [{"type": "text", "text": str(payload["text"])}]
        elif "tool" in payload:
            # Copy the payload: the script is built once in __init__, so a caller
            # mutating its dict afterwards must not rewrite what the model "said".
            tool = payload["tool"] or {}
            if also_text:
                blocks.append({"type": "text", "text": str(also_text)})
            blocks.append({"type": "tool_use", "id": tool.get("id", ""), "name": tool.get("name", ""), "input": dict(tool.get("input", {}) or {})})
        elif "tools" in payload:
            for tool in payload["tools"] or ():
                if isinstance(tool, dict):
                    blocks.append({"type": "tool_use", "id": tool.get("id", ""), "name": tool.get("name", ""), "input": dict(tool.get("input", {}) or {})})
                else:
                    blocks.append(tool)
        elif not payload:
            blocks = []
        else:
            raise TypeError(f"unsupported scripted turn keys: {', '.join(sorted(payload))}")
        leftover = sorted(key for key in payload if key not in {"tool", "tools", "blocks", "content", "text"})
        if leftover:
            raise TypeError(f"unsupported scripted turn keys: {', '.join(leftover)}")
        if not stop_reason:
            has_tool = any(isinstance(block, dict) and block.get("type") == "tool_use" for block in blocks)
            stop_reason = "tool_use" if has_tool else "end_turn"
        return ScriptedTurn(blocks=tuple(blocks), usage=usage, stop_reason=stop_reason, raises=raises)
    if isinstance(turn, (list, tuple)):
        return ScriptedTurn(blocks=tuple(turn), stop_reason="tool_use")
    raise TypeError(f"unsupported scripted turn: {type(turn).__name__}")


class ScriptedProvider(Provider):
    """Plays back a fixed list of turns."""

    name = "scripted"

    def __init__(
        self,
        turns: Iterable[Any] = (),
        *,
        model: str = "scripted",
        default_usage: Usage | dict[str, Any] | None = None,
        on_exhausted: str = "error",
    ) -> None:
        self.turns: list[ScriptedTurn] = [_coerce(turn) for turn in turns]
        self.model = model
        self.default_usage = _usage(default_usage)
        if on_exhausted not in {"error", "repeat_last", "stop"}:
            raise ValueError("on_exhausted must be 'error', 'repeat_last', or 'stop'")
        self.on_exhausted = on_exhausted
        self.requests: list[GenerationRequest] = []
        self.cursor = 0

    # -- Provider API ------------------------------------------------------
    def generate(self, request: GenerationRequest) -> Generation:
        self.requests.append(request)
        if self.cursor >= len(self.turns):
            return self._exhausted(request)
        turn = self.turns[self.cursor]
        self.cursor += 1
        if turn.raises is not None:
            raise turn.raises
        usage = turn.usage if turn.usage.total_tokens else self.default_usage
        return Generation(
            content=coerce_blocks(turn.blocks),
            usage=usage,
            stop_reason=turn.stop_reason,
            model=self.model,
        )

    # -- helpers -----------------------------------------------------------
    def _exhausted(self, request: GenerationRequest) -> Generation:
        if self.on_exhausted == "stop":
            return Generation(content=coerce_blocks(["(script exhausted)"]), model=self.model)
        if self.on_exhausted == "repeat_last" and self.turns:
            turn = self.turns[-1]
            if turn.raises is not None:
                raise turn.raises
            return Generation(content=coerce_blocks(turn.blocks), usage=turn.usage, stop_reason="end_turn", model=self.model)
        raise ProviderError(
            "ScriptedProvider exhausted after "
            f"{len(self.turns)} scripted turn(s); the loop asked for turn "
            f"{request.turn_index or self.cursor + 1}. Either script more turns "
            "or lower max_turns."
        )

    def pending(self) -> int:
        return max(0, len(self.turns) - self.cursor)

    def last_request(self) -> GenerationRequest | None:
        return self.requests[-1] if self.requests else None

    def sent_tool_results(self) -> list[dict[str, Any]]:
        """Every tool_result block the loop has handed back, in order."""
        found: list[dict[str, Any]] = []
        for request in self.requests:
            for message in request.messages:
                for block in message.get("content", []):
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        found.append(block)
        return found

    def sent_tool_errors(self) -> list[str]:
        return [
            _result_text(block) for block in self.sent_tool_results() if block.get("is_error")
        ]

    def message_roles(self) -> list[str]:
        return [message["role"] for request in self.requests for message in request.messages]


def _result_text(block: dict[str, Any]) -> str:
    content = block.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(str(item.get("text", "")) for item in content if isinstance(item, dict))
    return str(content)


__all__ = ["ScriptedProvider", "ScriptedTurn"]
