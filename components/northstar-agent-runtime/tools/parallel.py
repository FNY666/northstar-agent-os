"""Classify which tools may share a concurrent execution batch.

The governed loop still evaluates **every** call through PreToolUse hooks and the
permission gate **serially** and **independently**. Parallelism is only the
handler body of tools that cannot race each other or the audit trail:

* kind ``read`` and not mutating (Read / Grep / LS / DescribeTools);
* not a delegation tool (``Task`` owns a nested run and shared budget roll-up);
* not ``exec`` / ``edit`` / ``network`` / ``other`` (Shell, Write, Edit, MCP, …).

A mixed turn (any non-parallel-safe call) falls back to full serial dispatch so
ordering, denials, and workspace mutations stay deterministic. That is the
honest default: concurrency is an acceleration of safe observation, never a
shortcut around the gate.
"""
from __future__ import annotations

from typing import Any

#: Kinds whose handlers only observe state. Anything else runs alone.
PARALLEL_SAFE_KINDS: frozenset[str] = frozenset({"read"})

#: Closed ceiling on concurrent workers a single turn may open. Operators may
#: only tighten via config; the runtime never exceeds this.
MAX_PARALLEL_TOOLS = 8
DEFAULT_PARALLEL_TOOLS = 1  # serial — explicit opt-in to concurrency


def clamp_parallel_tools(value: Any) -> int:
    """Validate and clamp a ``parallel_tools`` setting to ``1..MAX_PARALLEL_TOOLS``."""
    if value is None or value == "":
        return DEFAULT_PARALLEL_TOOLS
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"parallel_tools must be an integer 1..{MAX_PARALLEL_TOOLS}; got {value!r}"
        )
    if value < 1:
        raise ValueError("parallel_tools must be >= 1 (1 = serial dispatch)")
    if value > MAX_PARALLEL_TOOLS:
        raise ValueError(
            f"parallel_tools cannot exceed {MAX_PARALLEL_TOOLS} "
            f"(a single turn opening more workers is a denial-of-service shape)"
        )
    return value


def is_parallel_safe_spec(spec: Any) -> bool:
    """True when ``spec``'s handler body may run beside another safe handler."""
    if spec is None:
        return False
    if getattr(spec, "is_delegation", False):
        return False
    if bool(getattr(spec, "is_mutating", True)):
        return False
    kind = getattr(spec, "kind", None) or "other"
    return kind in PARALLEL_SAFE_KINDS


def batch_is_parallel_safe(specs: list[Any]) -> bool:
    """True when every spec in the turn is parallel-safe (and there is more than one)."""
    if len(specs) < 2:
        return False
    return all(is_parallel_safe_spec(spec) for spec in specs)


__all__ = [
    "DEFAULT_PARALLEL_TOOLS",
    "MAX_PARALLEL_TOOLS",
    "PARALLEL_SAFE_KINDS",
    "batch_is_parallel_safe",
    "clamp_parallel_tools",
    "is_parallel_safe_spec",
]
