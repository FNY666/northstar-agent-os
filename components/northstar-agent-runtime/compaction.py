"""Context compaction that only ever cuts at a safe boundary.

A cut is **safe** when neither side of it is left dangling:

* the retained prefix must not end with a ``tool_use`` whose ``tool_result`` is
  being summarized away;
* the kept suffix must not start with a ``tool_result`` whose ``tool_use`` was
  summarized away.

Cut anywhere else and the next request carries an orphaned block, which the
Messages API rejects outright - the run dies with a 400 that looks like a provider
bug and is really a compaction bug. When no safe cut exists in the searchable
window, compaction is skipped and reported, never forced.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from providers.base import (
    AssistantMessage,
    COMPACT_HEADER,
    SystemMessage,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    estimate_transcript_tokens,
)

DEFAULT_KEEP_MESSAGES = 4
DEFAULT_MIN_CUT = 1

SUMMARY_HEADER = "[Earlier conversation summary]"


@dataclass(frozen=True)
class CompactionOutcome:
    """What compaction did, or exactly why it refused to."""

    performed: bool = False
    reason: str = ""
    transcript: tuple[Any, ...] = ()
    cut: int = -1
    dropped_messages: int = 0
    tokens_before: int = 0
    tokens_after: int = 0
    summary: str = ""
    boundary: SystemMessage | None = None
    summary_source: str = "extractive"

    def as_dict(self) -> dict[str, Any]:
        return {
            "performed": self.performed,
            "reason": self.reason,
            "cut": self.cut,
            "dropped_messages": self.dropped_messages,
            "tokens_before": self.tokens_before,
            "tokens_after": self.tokens_after,
            "tokens_saved": max(0, self.tokens_before - self.tokens_after),
            "summary_chars": len(self.summary),
            "summary_source": self.summary_source,
        }


# ---------------------------------------------------------------------------
# Boundary analysis
# ---------------------------------------------------------------------------


def tool_use_ids(messages: Sequence[Any]) -> list[str]:
    ids: list[str] = []
    for message in messages:
        if isinstance(message, AssistantMessage):
            ids.extend(call.id for call in message.tool_uses)
    return ids


def tool_result_ids(messages: Sequence[Any]) -> list[str]:
    ids: list[str] = []
    for message in messages:
        if isinstance(message, UserMessage):
            ids.extend(result.tool_use_id for result in message.tool_results)
    return ids


def pending_tool_uses(messages: Sequence[Any]) -> tuple[str, ...]:
    """``tool_use`` ids that have no ``tool_result`` yet.

    Non-empty means the loop is mid-tool-execution, and no cut below the last
    message is legal until the results land.
    """
    answered = set(tool_result_ids(messages))
    return tuple(call_id for call_id in tool_use_ids(messages) if call_id not in answered)


def orphaned_tool_results(messages: Sequence[Any], *, answered_by: Sequence[Any]) -> tuple[str, ...]:
    """``tool_result`` ids whose matching ``tool_use`` lives in ``answered_by``."""
    asked = set(tool_use_ids(answered_by))
    if not asked:
        return ()
    return tuple(result_id for result_id in tool_result_ids(messages) if result_id in asked)


def is_safe_cut(transcript: Sequence[Any], cut: int) -> bool:
    """True when ``transcript[:cut]`` can be replaced by a summary."""
    if not isinstance(cut, int) or cut < 0 or cut > len(transcript):
        return False
    prefix = transcript[:cut]
    suffix = transcript[cut:]
    if pending_tool_uses(prefix):
        return False
    if orphaned_tool_results(suffix, answered_by=prefix):
        return False
    return True


def safe_cuts(transcript: Sequence[Any]) -> tuple[int, ...]:
    return tuple(index for index in range(len(transcript) + 1) if is_safe_cut(transcript, index))


def latest_safe_cut(
    transcript: Sequence[Any],
    *,
    max_cut: int | None = None,
    min_cut: int = DEFAULT_MIN_CUT,
) -> int | None:
    """Greatest legal cut no later than ``max_cut``. ``None`` when there is none."""
    high = len(transcript) if max_cut is None else min(max_cut, len(transcript))
    for index in range(high, min_cut - 1, -1):
        if is_safe_cut(transcript, index):
            return index
    return None


# ---------------------------------------------------------------------------
# Summarisation
# ---------------------------------------------------------------------------


def extractive_summary(messages: Sequence[Any], *, max_chars: int = 4000, snippet_chars: int = 220) -> str:
    """Deterministic, provider-free summary.

    The default summariser is deliberately not a model call: compaction must not
    consume budget, must not need a second API round trip, and must be
    reproducible in tests. Hosts that want a model-written summary pass their own
    ``summarizer`` callable.
    """
    lines: list[str] = [SUMMARY_HEADER]
    for message in messages:
        if isinstance(message, SystemMessage):
            if message.subtype == "compact_boundary" and message.content:
                lines.append(f"- earlier summary: {_clip(message.content, snippet_chars)}")
            continue
        if isinstance(message, UserMessage):
            text = message.text.strip()
            if text:
                lines.append(f"- user: {_clip(text, snippet_chars)}")
            for result in message.tool_results:
                flag = "error" if result.is_error else "ok"
                lines.append(f"- tool_result[{flag}]: {_clip(result.text(), snippet_chars)}")
            continue
        if isinstance(message, AssistantMessage):
            text = message.text.strip()
            if text:
                lines.append(f"- assistant: {_clip(text, snippet_chars)}")
            for call in message.tool_uses:
                rendered = ", ".join(f"{key}={_clip(str(value), 40)}" for key, value in sorted(call.input.items()))
                lines.append(f"- called {call.name}({rendered})")
    summary = "\n".join(lines)
    if len(summary) > max_chars:
        summary = summary[:max_chars] + "\n- [summary truncated]"
    return summary


def _clip(text: str, limit: int) -> str:
    single = " ".join(text.split())
    return single if len(single) <= limit else single[: limit - 3] + "..."


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def should_compact(transcript: Sequence[Any], threshold_tokens: int | None) -> bool:
    if not threshold_tokens or threshold_tokens <= 0:
        return False
    return estimate_transcript_tokens(transcript) > threshold_tokens


def compact(
    transcript: Sequence[Any],
    *,
    threshold_tokens: int | None = None,
    force: bool = False,
    keep_messages: int = DEFAULT_KEEP_MESSAGES,
    summarizer: Callable[[Sequence[Any]], str] | None = None,
    min_cut: int = DEFAULT_MIN_CUT,
    instructions: str = "",
) -> CompactionOutcome:
    """Summarise a safe prefix of ``transcript``; keep the tail verbatim.

    ``keep_messages`` sets the minimum tail that is never summarized, so the model
    always sees the most recent exchanges in full. Returns ``performed=False`` with
    a reason whenever a legal cut cannot be found.
    """
    original = tuple(transcript)
    tokens_before = estimate_transcript_tokens(original)
    if not force and not should_compact(original, threshold_tokens):
        return CompactionOutcome(
            performed=False,
            reason="transcript is below the compaction threshold",
            transcript=original,
            tokens_before=tokens_before,
            tokens_after=tokens_before,
        )
    keep = max(0, int(keep_messages))
    max_cut = len(original) - keep
    if max_cut < 1:
        return CompactionOutcome(
            performed=False,
            reason="the transcript is no longer than the retained tail, so there is nothing to summarise",
            transcript=original,
            tokens_before=tokens_before,
            tokens_after=tokens_before,
        )
    cut = latest_safe_cut(original, max_cut=max_cut, min_cut=min(min_cut, max_cut))
    if cut is not None and cut <= 0:
        cut = None
    if cut is None:
        return CompactionOutcome(
            performed=False,
            reason=(
                "no safe compaction boundary: the transcript is mid tool exchange, "
                "so cutting here would orphan a tool_use or a tool_result"
            ),
            transcript=original,
            tokens_before=tokens_before,
            tokens_after=tokens_before,
        )
    prefix = original[:cut]
    kept = original[cut:]
    if summarizer is None:
        summary = extractive_summary(prefix)
        source = "extractive"
    else:
        written = str(summarizer(prefix) or "").strip()
        # An empty custom summary would silently delete context, so the
        # extractive fallback takes over - and the reported source says so.
        summary = written or extractive_summary(prefix)
        source = "provider" if written else "extractive_fallback"
    if instructions:
        summary = f"{summary}\n- host compaction instruction: {instructions}"
    boundary_data = {
        "cut": cut,
        "dropped_messages": len(prefix),
        "kept_messages": len(kept),
        "tokens_before": tokens_before,
        "summary_source": source,
    }
    boundary = SystemMessage(subtype="compact_boundary", content=summary, data=boundary_data)
    new_transcript = (boundary,) + tuple(kept)
    # The estimate needs the boundary message in place, and the boundary's data
    # dict is shared, so the after-count lands in the event the host records.
    tokens_after = estimate_transcript_tokens(new_transcript)
    boundary_data["tokens_after"] = tokens_after
    return CompactionOutcome(
        performed=True,
        reason=f"summarised {len(prefix)} message(s) at index {cut}",
        transcript=new_transcript,
        cut=cut,
        dropped_messages=len(prefix),
        tokens_before=tokens_before,
        tokens_after=estimate_transcript_tokens(new_transcript),
        summary=summary,
        boundary=boundary,
        summary_source=source,
    )


def summary_block(outcome: CompactionOutcome) -> dict[str, Any]:
    payload = outcome.as_dict()
    payload["header"] = COMPACT_HEADER.strip()
    return payload


__all__ = [
    "DEFAULT_KEEP_MESSAGES",
    "SUMMARY_HEADER",
    "CompactionOutcome",
    "compact",
    "extractive_summary",
    "is_safe_cut",
    "latest_safe_cut",
    "orphaned_tool_results",
    "pending_tool_uses",
    "safe_cuts",
    "should_compact",
    "summary_block",
    "tool_result_ids",
    "tool_use_ids",
]
