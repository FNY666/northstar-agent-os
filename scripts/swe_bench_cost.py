"""Read what a run cost from its evidence bundle.

The runtime already accounts for every turn: tokens, money, tool calls
and wall time are in the session transcript's result event.  A
measurement record that leaves them out cannot say what a resolved
instance cost, which is the other half of "how well did this go".

The reading is defensive on purpose.  A missing transcript, a truncated
line or a bundle without a result event means the cost is unknown, and
an unknown cost is reported as unknown rather than as zero.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

USAGE_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


def _zero_usage() -> dict[str, int]:
    return {field: 0 for field in USAGE_FIELDS}


def _events(transcript: Path) -> list[dict[str, Any]]:
    """The events of a session transcript, in order.

    A truncated line is skipped rather than fatal: the transcript is
    written while the run is going on, and the last line may be half
    written.
    """
    try:
        lines = transcript.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _result_event(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The result event of a session transcript, if it has one."""
    for event in reversed(events):
        if event.get("type") == "result" or "total_usage" in event:
            return event
    return None


def _last_tool_calls(events: list[dict[str, Any]]) -> int | None:
    """The tool calls of the last assistant message that made any."""
    for event in reversed(events):
        calls = event.get("tool_calls")
        if isinstance(calls, int):
            return calls
    return None


def read_usage(evidence_root: Path) -> dict[str, Any]:
    """What one run cost, as recorded in its evidence bundle."""
    empty: dict[str, Any] = {
        "usage": _zero_usage(),
        "cost_usd": None,
        "duration_ms": None,
        "tool_calls": None,
        "num_turns": None,
    }
    if not evidence_root.is_dir():
        return empty
    run_dirs = sorted(path for path in evidence_root.iterdir() if path.is_dir())
    if len(run_dirs) != 1:
        return empty
    sessions = run_dirs[0] / "sessions"
    if not sessions.is_dir():
        return empty
    transcripts = sorted(sessions.glob("*.jsonl"))
    if not transcripts:
        return empty
    events = _events(transcripts[-1])
    event = _result_event(events)
    if event is None:
        return empty

    usage = event.get("total_usage")
    if not isinstance(usage, dict):
        usage = {}
    counted = _zero_usage()
    for field in USAGE_FIELDS:
        value = usage.get(field)
        if isinstance(value, (int, float)):
            counted[field] = int(value)

    cost = event.get("total_cost_usd")
    duration = event.get("duration_ms")
    calls = event.get("tool_calls")
    if not isinstance(calls, (int, float)):
        calls = _last_tool_calls(events)
    turns = event.get("num_turns")
    return {
        "usage": counted,
        "cost_usd": float(cost) if isinstance(cost, (int, float)) else None,
        "duration_ms": int(duration) if isinstance(duration, (int, float)) else None,
        "tool_calls": int(calls) if isinstance(calls, (int, float)) else None,
        "num_turns": int(turns) if isinstance(turns, (int, float)) else None,
    }


def total_usage(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Sum the cost of a list of per-instance receipts.

    Instances whose cost is unknown are counted, so the sum is never
    mistaken for the cost of everything that ran.
    """
    usage = _zero_usage()
    cost = 0.0
    unknown_cost = 0
    unknown_usage = 0
    duration_ms = 0
    tool_calls = 0
    num_turns = 0
    known = 0
    for receipt in receipts:
        entry = receipt.get("usage") or {}
        counted = isinstance(entry, dict) and any(
            isinstance(entry.get(field), (int, float)) and entry.get(field)
            for field in USAGE_FIELDS
        )
        if not counted:
            unknown_usage += 1
        else:
            for field in USAGE_FIELDS:
                value = entry.get(field)
                if isinstance(value, (int, float)):
                    usage[field] += int(value)
            known += 1
        amount = receipt.get("cost_usd")
        if isinstance(amount, (int, float)):
            cost += float(amount)
        else:
            unknown_cost += 1
        for key, target in (
            ("duration_ms", "duration_ms"),
            ("tool_calls", "tool_calls"),
            ("num_turns", "num_turns"),
        ):
            value = receipt.get(key)
            if isinstance(value, (int, float)):
                if target == "duration_ms":
                    duration_ms += int(value)
                elif target == "tool_calls":
                    tool_calls += int(value)
                else:
                    num_turns += int(value)
    return {
        "usage": usage,
        "cost_usd": round(cost, 6),
        "instances_with_cost": known,
        "instances_without_cost": unknown_cost,
        "instances_without_usage": unknown_usage,
        "duration_ms": duration_ms,
        "tool_calls": tool_calls,
        "num_turns": num_turns,
    }
