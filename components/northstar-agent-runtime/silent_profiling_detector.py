"""WebMCP Silent Profiling detector: catch exfiltration through helpfulness.

"Silent Profiling" is the exfiltration shape where no single tool call is
malicious: the agent issues many individually-benign reads that collectively
assemble a profile of the user or the host. One contact read is helpful;
two hundred contact reads is exfiltration. The MCP/tool layer sees each
call in isolation and waves it through — the *pattern across calls* is the
only place the attack is visible.

This is the WebMCP analogue of the BSI position on indirect prompt
injection: the risk is *intrinsic* to an agent with broad read access, not
a bug in any one tool. A detector cannot distinguish "the user asked for
all contacts" from "the model is harvesting contacts" from the calls
alone — it can only surface the shape (volume, breadth, coverage) so the
approval layer can ask the question.

Design:

* ``ToolCall`` is the frozen per-call record: tool name, the data type it
  touched, an optional item id (for coverage accounting), and a
  caller-supplied integer sequence number. No wall-clock anywhere.
* ``analyze_calls(tool_calls)`` folds a call sequence into a frozen
  ``ProfilingPattern``: total ``call_count``, the ``data_types`` touched,
  per-signal scores, and the aggregate ``suspicion_score``.
* ``detect_profiling(tool_calls)`` is the boolean checkpoint: ``True``
  when ``suspicion_score`` reaches ``PROFILING_THRESHOLD``.
* Three independent signals, each in [0, 1], each interpretable on its
  own; the aggregate is the max (fail toward surfacing, never toward
  hiding):
  - **volume**: many small reads of one sensitive type. ``count / 10``
    capped at 1 — ten reads of contacts is already a list, not a lookup.
  - **breadth**: reads spanning distinct high-sensitivity types.
    ``distinct / 3`` capped at 1 — contacts + messages + location is a
    person, not a task.
  - **coverage**: fraction of a type's items touched, when the caller
    supplies per-type totals. Reading 80 of 100 contacts is harvesting
    even at a polite pace.
* Sensitivity tiers are fixed: HIGH (contacts, messages, emails,
  location, credentials, private files), MEDIUM (calendar, photos, notes,
  browsing history), LOW (everything else). Only HIGH types drive the
  volume and breadth signals; MEDIUM/LOW reads are counted but never
  alarming on their own.

Fail-closed throughout: a non-list input is a programming error
(``TypeError``); an empty call list has no pattern (``False``); unknown
data types are treated as LOW (never alarming, still counted).

Honest scope: this is a *shape* detector on host-reported call records.
It cannot see intent, cannot distinguish user-requested bulk export from
harvesting, and cannot observe calls the host never logged. A clean
verdict means "no known profiling shape", never "no exfiltration".
Pair with per-call authorization (``skill_wiring``) and the audit trail
for the full picture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional, Sequence

#: Module version pin, stamped on records for auditability.
SILENT_PROFILING_VERSION = "silent-profiling-detector.v1"

#: Schema pin for the record envelope.
SCHEMA_PIN = "northstar.silent-profiling-detector.v1"

#: Reads of one HIGH-sensitivity type at or above this count saturate the
#: volume signal. Ten is a list, not a lookup.
VOLUME_THRESHOLD = 10

#: Distinct HIGH-sensitivity types at or above this count saturate the
#: breadth signal. Three types is a person, not a task.
BREADTH_THRESHOLD = 3

#: Aggregate suspicion at or above this value trips the detector.
PROFILING_THRESHOLD = 0.7

#: Data types whose bulk reading is inherently profiling-shaped.
HIGH_SENSITIVITY_TYPES = frozenset({
    "contacts",
    "messages",
    "emails",
    "location",
    "credentials",
    "files_private",
    "call_history",
    "payment_history",
})

#: Data types worth counting but never alarming on their own.
MEDIUM_SENSITIVITY_TYPES = frozenset({
    "calendar",
    "photos",
    "notes",
    "browsing_history",
    "files_shared",
    "tasks",
})


def sensitivity_of(data_type: str) -> str:
    """Return the sensitivity tier for a data type: high / medium / low."""
    if data_type in HIGH_SENSITIVITY_TYPES:
        return "high"
    if data_type in MEDIUM_SENSITIVITY_TYPES:
        return "medium"
    return "low"


@dataclass(frozen=True)
class ToolCall:
    """One observed tool call touching a data type.

    ``item_id`` identifies the specific item read (a contact id, a message
    id) so coverage can be computed; ``None`` when the call has no
    per-item granularity. ``seq`` is a caller-supplied integer ordering
    key — no wall-clock.
    """

    tool_name: str
    data_type: str
    seq: int
    item_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.tool_name, str) or not self.tool_name:
            raise ValueError("tool_name must be a non-empty string")
        if not isinstance(self.data_type, str) or not self.data_type:
            raise ValueError("data_type must be a non-empty string")
        if isinstance(self.seq, bool) or not isinstance(self.seq, int):
            raise ValueError("seq must be an integer")
        if self.seq < 0:
            raise ValueError("seq must be non-negative")
        if self.item_id is not None and (
            not isinstance(self.item_id, str) or not self.item_id
        ):
            raise ValueError("item_id must be a non-empty string or None")


@dataclass(frozen=True)
class ProfilingPattern:
    """The folded shape of a call sequence.

    ``call_count`` is the total number of calls analyzed; ``data_types``
    the distinct types touched; ``suspicion_score`` the aggregate in
    [0, 1]; the per-signal scores expose *why* the aggregate fired.
    ``version`` pins the detector version for auditability.
    """

    call_count: int
    data_types: frozenset
    suspicion_score: float
    volume_score: float
    breadth_score: float
    coverage_score: float
    version: str = SILENT_PROFILING_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.call_count, bool) or not isinstance(self.call_count, int):
            raise ValueError("call_count must be an integer")
        if self.call_count < 0:
            raise ValueError("call_count must be non-negative")
        for name in ("suspicion_score", "volume_score", "breadth_score", "coverage_score"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a number")
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "call_count": self.call_count,
            "data_types": sorted(self.data_types),
            "suspicion_score": self.suspicion_score,
            "volume_score": self.volume_score,
            "breadth_score": self.breadth_score,
            "coverage_score": self.coverage_score,
        }


def _coerce_calls(tool_calls: Sequence[Any]) -> list[ToolCall]:
    """Validate the input and return a list of ToolCall records."""
    if isinstance(tool_calls, (str, bytes)) or not isinstance(tool_calls, Sequence):
        raise TypeError("tool_calls must be a sequence of ToolCall records")
    coerced: list[ToolCall] = []
    for item in tool_calls:
        if isinstance(item, ToolCall):
            coerced.append(item)
        elif isinstance(item, Mapping):
            coerced.append(
                ToolCall(
                    tool_name=item.get("tool_name", item.get("tool", "")),
                    data_type=item.get("data_type", item.get("type", "")),
                    seq=item.get("seq", 0),
                    item_id=item.get("item_id"),
                )
            )
        else:
            raise TypeError(
                "tool_calls entries must be ToolCall records or mappings"
            )
    return coerced


def analyze_calls(
    tool_calls: Sequence[Any],
    *,
    totals: Optional[Mapping[str, int]] = None,
) -> ProfilingPattern:
    """Fold a call sequence into a ProfilingPattern.

    ``totals`` optionally maps a data type to its total item count so the
    coverage signal can be computed (e.g. ``{"contacts": 100}``). Types
    absent from ``totals`` simply contribute no coverage signal.
    """
    calls = _coerce_calls(tool_calls)
    totals = dict(totals) if totals else {}

    call_count = len(calls)
    data_types = frozenset(c.data_type for c in calls)

    # Volume: worst per-type read count among HIGH types, normalized.
    per_type_counts: dict[str, int] = {}
    for c in calls:
        if sensitivity_of(c.data_type) == "high":
            per_type_counts[c.data_type] = per_type_counts.get(c.data_type, 0) + 1
    worst_volume = max(per_type_counts.values(), default=0)
    volume_score = min(1.0, worst_volume / VOLUME_THRESHOLD)

    # Breadth: distinct HIGH types touched, normalized.
    distinct_high = {c.data_type for c in calls if sensitivity_of(c.data_type) == "high"}
    breadth_score = min(1.0, len(distinct_high) / BREADTH_THRESHOLD)

    # Coverage: worst fraction of a type's items touched, where totals known.
    coverage_score = 0.0
    if totals:
        seen_items: dict[str, set[str]] = {}
        for c in calls:
            if c.item_id is not None and c.data_type in totals:
                seen_items.setdefault(c.data_type, set()).add(c.item_id)
        for dtype, seen in seen_items.items():
            total = totals.get(dtype, 0)
            if isinstance(total, int) and total > 0:
                coverage_score = max(coverage_score, min(1.0, len(seen) / total))

    suspicion_score = max(volume_score, breadth_score, coverage_score)

    return ProfilingPattern(
        call_count=call_count,
        data_types=data_types,
        suspicion_score=suspicion_score,
        volume_score=volume_score,
        breadth_score=breadth_score,
        coverage_score=coverage_score,
    )


def detect_profiling(
    tool_calls: Sequence[Any],
    *,
    totals: Optional[Mapping[str, int]] = None,
    threshold: float = PROFILING_THRESHOLD,
) -> bool:
    """Return True when the call sequence matches a profiling shape.

    Never raises on well-formed input; an empty sequence has no pattern
    and returns False. ``TypeError`` on malformed input is a programming
    error, not a policy verdict.
    """
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError("threshold must be a number")
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be in [0, 1]")
    pattern = analyze_calls(tool_calls, totals=totals)
    return pattern.suspicion_score >= threshold


def profiling_audit_event(
    pattern: ProfilingPattern,
    *,
    seq: int,
    session_id: str = "",
) -> dict:
    """Build an audit-shaped record for a profiling analysis."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative integer")
    return {
        "schema": SCHEMA_PIN,
        "type": "silent-profiling-analysis",
        "seq": seq,
        "session_id": session_id,
        "pattern": pattern.as_dict(),
        "tripped": pattern.suspicion_score >= PROFILING_THRESHOLD,
    }


def main() -> None:
    """Self-check: benign session stays quiet, harvesting trips."""
    benign = [
        ToolCall(tool_name="calendar.read", data_type="calendar", seq=i)
        for i in range(3)
    ]
    assert not detect_profiling(benign)

    harvest = [
        ToolCall(
            tool_name="contacts.read",
            data_type="contacts",
            seq=i,
            item_id=f"contact-{i}",
        )
        for i in range(12)
    ]
    assert detect_profiling(harvest)

    broad = [
        ToolCall(tool_name="contacts.read", data_type="contacts", seq=0),
        ToolCall(tool_name="messages.read", data_type="messages", seq=1),
        ToolCall(tool_name="location.get", data_type="location", seq=2),
    ]
    assert detect_profiling(broad)

    print("silent-profiling-detector OK: benign quiet, harvest + breadth trip")


if __name__ == "__main__":
    main()
