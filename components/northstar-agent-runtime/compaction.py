"""Conversation compaction at safe boundaries only.

A boundary is *safe* when the conversation prefix kept up to that index can
be sent to the API without dangling ``tool_use`` blocks: an assistant message
carrying ``tool_use`` must never be the last kept message, because its
``tool_result`` would live in the dropped part and the API rejects the
request. ``compact_messages`` therefore backs up from the requested cut
point to the nearest safe boundary.
"""
from __future__ import annotations

import json
from typing import Any, Sequence

COMPACT_MARKER = "[context compacted]"


def _content_blocks(message: dict[str, Any]) -> list[dict[str, Any]]:
    content = message.get("content")
    if isinstance(content, str):
        return []
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    return []


def has_pending_tool_use(message: dict[str, Any]) -> bool:
    """True when this assistant message carries tool_use blocks whose results
    necessarily come after it."""
    if message.get("role") != "assistant":
        return False
    return any(b.get("type") == "tool_use" for b in _content_blocks(message))


def is_safe_boundary(messages: Sequence[dict[str, Any]], index: int) -> bool:
    """True when ``messages[:index]`` has no orphaned tool_use."""
    if index <= 0:
        return True
    if index > len(messages):
        index = len(messages)
    return not has_pending_tool_use(messages[index - 1])


def find_safe_boundary(messages: Sequence[dict[str, Any]], limit: int) -> int:
    """Largest safe index <= ``limit`` (backing up over pending tool_use)."""
    index = max(0, min(limit, len(messages)))
    while index > 0 and not is_safe_boundary(messages, index):
        index -= 1
    return index


def estimate_tokens(messages: Sequence[dict[str, Any]]) -> int:
    """Cheap deterministic token estimate (4 chars per token)."""
    raw = json.dumps(list(messages), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return max(1, (len(raw) + 3) // 4)


def summarize(dropped: Sequence[dict[str, Any]]) -> str:
    turns = sum(1 for m in dropped if m.get("role") == "assistant")
    tools: list[str] = []
    for m in dropped:
        for b in _content_blocks(m):
            if b.get("type") == "tool_use":
                tools.append(str(b.get("name", "?")))
    tool_note = ", ".join(tools) if tools else "none"
    return (
        f"{COMPACT_MARKER} {len(dropped)} earlier messages "
        f"({turns} assistant turns; tools used: {tool_note}) "
        "were summarized and removed from the active window. "
        "Answer from the remaining context and re-read files if you need details."
    )


def compact_messages(
    messages: Sequence[dict[str, Any]], keep: int = 6
) -> tuple[list[dict[str, Any]], int]:
    """Drop the oldest messages at a safe boundary, keeping the newest ``keep``.

    Returns ``(new_messages, dropped_count)``. A no-op (dropped_count == 0)
    when nothing can safely be dropped. The summary is a user message, so the
    rebuilt conversation is still valid for the API.
    """
    total = len(messages)
    boundary = find_safe_boundary(messages, total - keep)
    if boundary < 1 or boundary >= total:
        return list(messages), 0
    dropped = messages[:boundary]
    rebuilt = [{"role": "user", "content": summarize(dropped)}] + list(messages[boundary:])
    return rebuilt, len(dropped)


def assert_valid_conversation(messages: Sequence[dict[str, Any]]) -> None:
    """Raise ValueError on a conversation the API would reject.

    Catches orphaned tool_use (no matching tool_result before the next
    assistant message) and trailing pending tool_use.
    """
    pending: set[str] = set()
    for message in messages:
        role = message.get("role")
        blocks = _content_blocks(message)
        if role == "assistant":
            for b in blocks:
                if b.get("type") == "tool_use":
                    tid = str(b.get("id", ""))
                    if tid in pending:
                        raise ValueError(f"conversation has duplicate tool_use: {tid}")
                    pending.add(tid)
        elif role == "user":
            for b in blocks:
                if b.get("type") == "tool_result":
                    tid = str(b.get("tool_use_id", ""))
                    if tid not in pending:
                        raise ValueError(f"tool_result without matching tool_use: {tid}")
                    pending.discard(tid)
    if pending:
        raise ValueError(f"conversation ends with pending tool_use: {sorted(pending)}")
