"""Stuck detector: five repetition patterns over Northstar session history.

What problem this solves
------------------------
A long-horizon Northstar run can loop forever: the same tool call, the same
failure, the same monologue, the same ping-pong between two tools.  Nothing in
the runtime stops it -- the run ends only when the budget or the context
window is exhausted.  The operations watchdog (``b173-watchdog.py``) watches
the *session* (compaction, no file changes, no commit); it cannot see a
repetition pattern *inside* a turn.  This module is the in-repo detector for
that inner loop.

Source of the thresholds
------------------------
The five patterns and their thresholds come from the OpenHands SDK guide
"Stuck Detector" (https://docs.openhands.dev/sdk/guides/agent-stuck-detector),
read on 2026-11-14.  That document is the source for:

* the five pattern names and their thresholds (4+ action-observation repeats,
  3+ action-error repeats, 3+ monologue messages, 6+ alternating cycles),
* the semantic comparison rules (action by tool name / action content /
  thought, observation by observation content / tool name, error by error
  message, message by content / source),
* the scope rule: only the history *after the last user message*.

Northstar extensions (not OpenHands content -- see docs/design/stuck-detector.md)
-------------------------------------------------------------------------------
* The input is Northstar's own session event stream (the JSONL transcript
  records written by ``sessions.py``), not OpenHands' Event objects.
* The context-window-error threshold (3 by default) is **Northstar's** number:
  the OpenHands document describes the pattern but gives no threshold.
* "6+ cycles" of the alternating pattern means **6 complete cycles** (A-B-A-B,
  12 steps), which is Northstar's reading of the OpenHands wording.
* The detector never halts anything.  It returns a structured verdict; whether
  the run stops is the caller's decision.
"""

from __future__ import annotations

import collections.abc
import json
from dataclasses import dataclass, field, replace
from typing import Any, Hashable, Sequence

__all__ = [
    "DEFAULT_THRESHOLDS",
    "PATTERN_ALTERNATING",
    "PATTERN_CONTEXT_WINDOW_ERRORS",
    "PATTERN_MONOLOGUE",
    "PATTERN_REPEAT_ACTION_ERROR",
    "PATTERN_REPEAT_ACTION_OBSERVATION",
    "STUCK_PATTERNS",
    "EvidencePointer",
    "StuckDetector",
    "StuckThresholds",
    "StuckVerdict",
    "detect",
    "is_stuck",
]

# ---------------------------------------------------------------------------
# Pattern names
# ---------------------------------------------------------------------------

#: The same action produces the same observation repeatedly (OpenHands: 4+).
PATTERN_REPEAT_ACTION_OBSERVATION = "repeat_action_observation"
#: The same action repeatedly results in errors (OpenHands: 3+).
PATTERN_REPEAT_ACTION_ERROR = "repeat_action_error"
#: The agent sends consecutive messages with no user input and no progress
#: (OpenHands: 3+).
PATTERN_MONOLOGUE = "monologue"
#: Two different action-observation pairs alternate ping-pong (OpenHands: 6+
#: cycles; Northstar counts *complete* cycles).
PATTERN_ALTERNATING = "alternating"
#: Repeated context-window errors (OpenHands names the pattern and gives no
#: number; the threshold here is Northstar's).
PATTERN_CONTEXT_WINDOW_ERRORS = "context_window_errors"

#: The five patterns, in the order the OpenHands document lists them.  The
#: detector reports the first one that trips, in this order.
STUCK_PATTERNS: tuple[str, ...] = (
    PATTERN_REPEAT_ACTION_OBSERVATION,
    PATTERN_REPEAT_ACTION_ERROR,
    PATTERN_MONOLOGUE,
    PATTERN_ALTERNATING,
    PATTERN_CONTEXT_WINDOW_ERRORS,
)

#: Input keys ignored when comparing actions: "ignoring IDs and metrics" in the
#: OpenHands document, plus the timestamps and counters a Northstar transcript
#: adds on top of them.  A tool that takes a business-level "id" argument
#: loses it too -- the detector compares *what the agent asked for*, and the
#: call identity is not part of that.
VOLATILE_INPUT_KEYS: frozenset[str] = frozenset({
    "id", "call_id", "tool_call_id", "tool_use_id", "uuid", "request_id",
    "metrics", "usage", "cost_usd", "session_id", "turn_index", "index",
    "timestamp", "ts", "time", "started_at", "finished_at", "duration_ms",
    "latency_ms", "elapsed_ms", "duration_s",
})

#: Substrings that mark an error as a context-window error.  The OpenHands
#: document names the pattern ("repeated context window errors") without
#: listing signals, so these are Northstar's.
CONTEXT_WINDOW_SIGNALS: tuple[str, ...] = (
    "context window",
    "context_window",
    "contextwindow",
    "context length",
    "context_length",
    "maximum context",
    "max context",
    "context limit",
    "context_limit",
    "context overflow",
    "context overflow",
    "too many tokens",
    "prompt is too long",
    "input is too long",
    "exceeds the context",
    "token limit",
    "input length exceeds",
)


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StuckThresholds:
    """Every threshold in one frozen record.

    The defaults are the numbers the OpenHands document states, except
    ``context_window_errors``, for which the document gives no number: 3 is
    Northstar's choice and is documented as such.
    """

    repeat_action_observation: int = 4
    repeat_action_error: int = 3
    monologue: int = 3
    alternating_cycles: int = 6
    context_window_errors: int = 3

    def as_dict(self) -> dict[str, int]:
        return {
            "repeat_action_observation": self.repeat_action_observation,
            "repeat_action_error": self.repeat_action_error,
            "monologue": self.monologue,
            "alternating_cycles": self.alternating_cycles,
            "context_window_errors": self.context_window_errors,
        }


DEFAULT_THRESHOLDS = StuckThresholds()


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidencePointer:
    """Where in the event history the evidence sits."""

    first_index: int = -1
    last_index: int = -1
    count: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "first_index": self.first_index,
            "last_index": self.last_index,
            "count": self.count,
        }


@dataclass(frozen=True)
class StuckVerdict:
    """The detector's answer.  It never stops a run by itself."""

    is_stuck: bool = False
    pattern: str = ""
    summary: str = ""
    evidence: tuple[dict[str, Any], ...] = ()
    evidence_pointer: EvidencePointer | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "is_stuck": self.is_stuck,
            "pattern": self.pattern,
            "summary": self.summary,
            "evidence": [dict(item) for item in self.evidence],
            "evidence_pointer": (
                self.evidence_pointer.as_dict() if self.evidence_pointer else None
            ),
        }


# ---------------------------------------------------------------------------
# Normalised events
# ---------------------------------------------------------------------------

#: Normalised event kinds.
KIND_ACTION = "action"
KIND_OBSERVATION = "observation"
KIND_ERROR = "error"
KIND_MESSAGE = "message"
KIND_USER_MESSAGE = "user_message"

#: Tool names whose successful result changes files on disk.  A file change is
#: "meaningful progress" for the monologue pattern.
FILE_MUTATING_TOOLS: frozenset[str] = frozenset({
    "write", "edit", "multiedit", "notebookedit", "apply_patch", "patch",
})


@dataclass(frozen=True)
class NormalizedEvent:
    """One event, reduced to the keys the detector compares.

    The keys are tuples of strings so that equality is the comparison, and so
    that a verdict can carry them as evidence without re-deriving anything.
    """

    index: int = -1
    kind: str = ""
    tool_name: str = ""
    #: (tool name, action content, thought) -- OpenHands' action key.
    action_key: tuple[str, ...] = ()
    #: (observation content, tool name) -- OpenHands' observation key.
    observation_key: tuple[str, ...] = ()
    #: (error message,) -- OpenHands' error key.
    error_key: tuple[str, ...] = ()
    #: (content, source) -- OpenHands' message key.
    message_key: tuple[str, ...] = ()
    thought: str = ""
    is_error: bool = False
    #: True when this event carries a file change (a successful write/edit).
    file_change: bool = False
    #: The tool call id, used only to link a result to its call.  It is never
    #: part of a comparison key.
    tool_use_id: str = ""
    #: The raw event, kept for evidence only.
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_progress(self) -> bool:
        """True when the event is meaningful progress for the monologue rule."""
        return self.file_change or (
            self.kind == KIND_OBSERVATION and not self.is_error
        )


def _canonical(value: Any) -> str:
    """A stable text form of a tool input, with the volatile keys removed."""
    if isinstance(value, dict):
        cleaned = {
            str(key): child
            for key, child in value.items()
            if str(key).lower() not in VOLATILE_INPUT_KEYS
        }
        return json.dumps(cleaned, ensure_ascii=False, sort_keys=True, default=str)
    if isinstance(value, (list, tuple)):
        return json.dumps(list(value), ensure_ascii=False, sort_keys=True, default=str)
    return str(value)


def _text_of(value: Any) -> str:
    """Flatten a content payload (str, block list, or dict) into text."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "text" in value:
            return str(value.get("text") or "")
        if value.get("type") == "tool_result":
            return _text_of(value.get("content"))
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    if isinstance(value, (list, tuple)):
        parts = [_text_of(item) for item in value]
        return "\n".join(part for part in parts if part)
    return str(value)


def _is_context_window_error(message: str) -> bool:
    lowered = message.lower()
    return any(signal in lowered for signal in CONTEXT_WINDOW_SIGNALS)


# ---------------------------------------------------------------------------
# Normalisation: Northstar session records -> comparable events
# ---------------------------------------------------------------------------

#: The session record types the detector reads.  ``assistant`` records carry
#: the tool_use and text blocks; ``tool_result`` records carry the results
#: (they are written as user-role records, because that is how the provider
#: sees them).
ACTION_RECORD_TYPES: frozenset[str] = frozenset({"assistant"})
OBSERVATION_RECORD_TYPES: frozenset[str] = frozenset({"tool_result"})
MESSAGE_RECORD_TYPES: frozenset[str] = frozenset({"assistant"})


def _blocks_of(record: dict[str, Any]) -> list[dict[str, Any]]:
    content = record.get("content")
    if isinstance(content, (list, tuple)):
        return [block for block in content if isinstance(block, dict)]
    if isinstance(content, dict):
        return [content]
    return []


def _thought_of(blocks: Sequence[dict[str, Any]]) -> str:
    """The thought attached to the action: the thinking block's text."""
    parts = [
        str(block.get("thinking") or block.get("text") or "")
        for block in blocks
        if block.get("type") == "thinking"
    ]
    return "\n".join(part for part in parts if part)


def _source_of(record: dict[str, Any]) -> str:
    """The message source: the agent that spoke."""
    source = record.get("agent")
    if isinstance(source, str) and source:
        return source
    role = record.get("role")
    return str(role) if isinstance(role, str) else ""


def _normalise_record(
    record: dict[str, Any],
    index: int,
) -> list[NormalizedEvent]:
    """Turn one session record into zero or more normalised events.

    Fail-closed: a block that cannot be normalised (no tool name, no content)
    yields no event at all.  It is not counted as "not a repeat" -- it simply
    does not participate in any comparison.
    """
    kind = str(record.get("type") or "")
    events: list[NormalizedEvent] = []
    blocks = _blocks_of(record)

    if kind in ACTION_RECORD_TYPES:
        tool_uses = [block for block in blocks if block.get("type") == "tool_use"]
        text_blocks = [block for block in blocks if block.get("type") == "text"]
        thinking = _thought_of(blocks)
        for block in tool_uses:
            name = str(block.get("name") or "")
            if not name:
                continue  # fail-closed: no tool name, no action key
            action_input = block.get("input")
            action_key = (name, _canonical(action_input), thinking)
            events.append(
                NormalizedEvent(
                    index=index,
                    kind=KIND_ACTION,
                    tool_name=name,
                    action_key=action_key,
                    thought=thinking,
                    tool_use_id=str(block.get("id") or ""),
                    raw=record,
                )
            )
        if text_blocks:
            content = "\n".join(str(block.get("text") or "") for block in text_blocks)
            if content.strip():
                events.append(
                    NormalizedEvent(
                        index=index,
                        kind=KIND_MESSAGE,
                        message_key=(content, _source_of(record)),
                        raw=record,
                    )
                )
        return events

    if kind == "user_prompt":
        # A user turn resets the detection window.  A meta prompt is host
        # context, not user input, so it does not.
        if record.get("is_meta"):
            return events
        content = "\n".join(
            str(block.get("text") or "")
            for block in blocks
            if block.get("type") == "text"
        )
        if content.strip():
            events.append(
                NormalizedEvent(
                    index=index,
                    kind=KIND_USER_MESSAGE,
                    message_key=(content, _source_of(record)),
                    raw=record,
                )
            )
        return events

    if kind in OBSERVATION_RECORD_TYPES:
        for block in blocks:
            if block.get("type") != "tool_result":
                continue
            content = _text_of(block.get("content"))
            is_error = bool(block.get("is_error"))
            tool_name = str(block.get("tool_name") or block.get("name") or "")
            observation_key = (content, tool_name)
            events.append(
                NormalizedEvent(
                    index=index,
                    kind=KIND_OBSERVATION,
                    tool_name=tool_name,
                    observation_key=observation_key,
                    is_error=is_error,
                    file_change=(
                        not is_error
                        and tool_name.lower() in FILE_MUTATING_TOOLS
                    ),
                    tool_use_id=str(block.get("tool_use_id") or ""),
                    raw=record,
                )
            )
            if is_error:
                events.append(
                    NormalizedEvent(
                        index=index,
                        kind=KIND_ERROR,
                        tool_name=tool_name,
                        error_key=(content,),
                        is_error=True,
                        tool_use_id=str(block.get("tool_use_id") or ""),
                        raw=record,
                    )
                )
        return events

    if kind == "denial":
        reason = str(record.get("reason") or record.get("detail") or "")
        if reason:
            events.append(
                NormalizedEvent(
                    index=index,
                    kind=KIND_ERROR,
                    tool_name=str(record.get("tool") or ""),
                    error_key=(reason,),
                    is_error=True,
                    raw=record,
                )
            )
        return events

    return events


def _records_to_events(
    records: Sequence[dict[str, Any]],
) -> list[NormalizedEvent]:
    """Normalise a whole history, keeping the record index on every event."""
    events: list[NormalizedEvent] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        events.extend(_normalise_record(record, index))
    return _resolve_observation_tools(events)


def _resolve_observation_tools(
    events: list[NormalizedEvent],
) -> list[NormalizedEvent]:
    """Give every observation the name of the tool that produced it.

    The transcript's ``tool_result`` block carries the call id but not the
    tool name, so the name is taken from the paired action.  This keeps the
    observation key "(observation content, tool name)" complete without
    inventing a name for an unpaired result.
    """
    names: dict[str, str] = {}
    for event in events:
        if event.kind == KIND_ACTION and event.tool_use_id:
            names.setdefault(event.tool_use_id, event.tool_name)
    resolved: list[NormalizedEvent] = []
    for event in events:
        if event.kind == KIND_OBSERVATION and not event.tool_name and event.tool_use_id:
            name = names.get(event.tool_use_id, "")
            if name:
                event = replace(
                    event,
                    tool_name=name,
                    observation_key=(event.observation_key[0], name),
                )
        resolved.append(event)
    return resolved


# ---------------------------------------------------------------------------
# Window and pairing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Pair:
    """An action and the observation that answered it."""

    action: NormalizedEvent
    observation: NormalizedEvent | None
    index: int

    @property
    def key(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        return (self.action.action_key, self.observation.observation_key if self.observation else ())


def _window_events(
    events: Sequence[NormalizedEvent],
) -> list[NormalizedEvent]:
    """Only the history after the last user message.

    The OpenHands document examines "the event history after the last user
    message".  A Northstar user turn is a ``user_prompt`` record that is not
    marked ``is_meta``: a meta prompt is host context, not user input, so it
    does not reset the window.
    """
    start = 0
    for position, event in enumerate(events):
        if event.kind == KIND_USER_MESSAGE:
            start = position + 1
    return list(events[start:])


def _build_pairs(events: Sequence[NormalizedEvent]) -> list[_Pair]:
    """Pair every action with the observation that answered it.

    The link is the tool call id, which the transcript carries on both sides.
    The id is never part of a comparison key -- it only says which result
    belongs to which call.

    The transcript's ``tool_result`` block carries the call id but not the tool
    name, so the name is taken from the paired action.  That keeps the
    observation key "(observation content, tool name)" complete without
    inventing a name for an unpaired result.
    """
    by_id: dict[str, NormalizedEvent] = {}
    for event in events:
        if event.kind == KIND_ACTION and event.tool_use_id:
            by_id.setdefault(event.tool_use_id, event)
    pairs: list[_Pair] = []
    for event in events:
        if event.kind != KIND_OBSERVATION:
            continue
        action = by_id.get(event.tool_use_id) if event.tool_use_id else None
        pairs.append(_Pair(action=action, observation=event, index=event.index))
    return pairs


# ---------------------------------------------------------------------------
# The five detectors
# ---------------------------------------------------------------------------


def _max_run(keys: Sequence[Hashable]) -> tuple[int, int, int]:
    """The longest run of one repeated key: (length, start, end).

    ``keys`` is a sequence of comparable keys; the run must be *consecutive*,
    because the OpenHands patterns describe a cycle, not a lifetime tally.
    """
    best = (0, 0, -1)
    start = 0
    for position in range(1, len(keys) + 1):
        if position == len(keys) or keys[position] != keys[start]:
            length = position - start
            if length > best[0]:
                best = (length, start, position - 1)
            start = position
    return best


def _detect_repeat_action_observation(
    pairs: Sequence[_Pair],
    thresholds: StuckThresholds,
) -> StuckVerdict | None:
    """The same action produces the same observation repeatedly (4+).

    Only *successful* observations count here.  A repeated failure is the
    other pattern (repeat_action_error), and counting it twice would let one
    failure run masquerade as an observation loop.
    """
    comparable = [
        pair for pair in pairs
        if pair.action is not None
        and pair.observation is not None
        and not pair.observation.is_error
    ]
    if len(comparable) < thresholds.repeat_action_observation:
        return None
    keys = [pair.key for pair in comparable]
    length, start, end = _max_run(keys)
    if length < thresholds.repeat_action_observation:
        return None
    action_key, observation_key = keys[start]
    first = comparable[start].index
    last = comparable[end].index
    return StuckVerdict(
        is_stuck=True,
        pattern=PATTERN_REPEAT_ACTION_OBSERVATION,
        summary=(
            f"the same action produced the same observation {length} times "
            f"in a row (threshold {thresholds.repeat_action_observation})"
        ),
        evidence=(
            {"action_key": list(action_key), "observation_key": list(observation_key)},
        ),
        evidence_pointer=EvidencePointer(first_index=first, last_index=last, count=length),
    )


def _detect_repeat_action_error(
    pairs: Sequence[_Pair],
    thresholds: StuckThresholds,
) -> StuckVerdict | None:
    """The same action repeatedly results in errors (3+).

    The count is per action key and counts *consecutive* errors of that key:
    a success of the same action resets it.  Another action running in between
    does not reset it -- the action is what is looping.
    """
    counts: dict[tuple[str, ...], int] = {}
    best: tuple[int, tuple[str, ...], int, int] = (0, (), -1, -1)
    for pair in pairs:
        if pair.action is None or pair.observation is None or not pair.observation.is_error:
            continue
        key = pair.action.action_key
        counts[key] = counts.get(key, 0) + 1
        current = counts[key]
        if current > best[0]:
            best = (current, key, pair.index, pair.index)
        elif current == best[0]:
            best = (current, key, best[2], pair.index)
    if best[0] < thresholds.repeat_action_error:
        return None
    count, key, first, last = best
    return StuckVerdict(
        is_stuck=True,
        pattern=PATTERN_REPEAT_ACTION_ERROR,
        summary=(
            f"the same action produced an error {count} times "
            f"(threshold {thresholds.repeat_action_error})"
        ),
        evidence=({"action_key": list(key), "count": count},),
        evidence_pointer=EvidencePointer(first_index=first, last_index=last, count=count),
    )


def _detect_monologue(
    events: Sequence[NormalizedEvent],
    thresholds: StuckThresholds,
) -> StuckVerdict | None:
    """The agent sends consecutive messages with no input and no progress (3+).

    "No meaningful progress" is Northstar's operational reading: a successful
    tool result or a file change resets the run.  The OpenHands document names
    the pattern and its threshold but does not define progress.

    The message key is (content, source), so the run is counted per source:
    two agents talking in turn are not one agent monologuing.
    """
    runs: dict[str, list[NormalizedEvent]] = {}
    order: list[str] = []

    def flush(source: str) -> None:
        runs[source] = []

    for event in events:
        if event.kind == KIND_USER_MESSAGE:
            for source in list(runs):
                flush(source)
            continue
        if event.kind == KIND_MESSAGE:
            source = event.message_key[1] if len(event.message_key) > 1 else ""
            if source not in runs:
                runs[source] = []
                order.append(source)
            runs[source].append(event)
            continue
        if event.is_progress:
            for source in list(runs):
                flush(source)
    best: list[NormalizedEvent] = []
    for source in order:
        if len(runs[source]) > len(best):
            best = list(runs[source])
    if len(best) < thresholds.monologue:
        return None
    return StuckVerdict(
        is_stuck=True,
        pattern=PATTERN_MONOLOGUE,
        summary=(
            f"the agent sent {len(best)} consecutive messages with no user input "
            f"and no progress (threshold {thresholds.monologue})"
        ),
        evidence=tuple({"message_key": list(event.message_key)} for event in best),
        evidence_pointer=EvidencePointer(
            first_index=best[0].index,
            last_index=best[-1].index,
            count=len(best),
        ),
    )


def _detect_alternating(
    pairs: Sequence[_Pair],
    thresholds: StuckThresholds,
) -> StuckVerdict | None:
    """Two different action-observation pairs alternate ping-pong (6+ cycles).

    Northstar counts *complete* cycles: A-B-A-B for 6 cycles is 12 steps.
    The OpenHands document says "6+ cycles" without defining a cycle.
    """
    comparable = [pair for pair in pairs if pair.action is not None]
    if len(comparable) < 2 * thresholds.alternating_cycles:
        return None
    keys = [pair.key for pair in comparable]
    best: tuple[int, int, int] = (0, 0, -1)
    start = 0
    while start + 1 < len(keys):
        if keys[start] == keys[start + 1]:
            start += 1
            continue
        position = start + 2
        while position < len(keys) and keys[position] == keys[position - 2]:
            position += 1
        length = position - start
        if length > best[0]:
            best = (length, start, position - 1)
        start = max(position, start + 1)
    length, first_pos, last_pos = best
    cycles = length // 2
    if cycles < thresholds.alternating_cycles:
        return None
    first_key, second_key = keys[first_pos], keys[first_pos + 1]
    return StuckVerdict(
        is_stuck=True,
        pattern=PATTERN_ALTERNATING,
        summary=(
            f"two different action-observation pairs alternated for {cycles} complete "
            f"cycles (threshold {thresholds.alternating_cycles})"
        ),
        evidence=(
            {"cycle_a": {"action_key": list(first_key[0]), "observation_key": list(first_key[1])}},
            {"cycle_b": {"action_key": list(second_key[0]), "observation_key": list(second_key[1])}},
        ),
        evidence_pointer=EvidencePointer(
            first_index=comparable[first_pos].index,
            last_index=comparable[last_pos].index,
            count=cycles,
        ),
    )


def _detect_context_window_errors(
    events: Sequence[NormalizedEvent],
    thresholds: StuckThresholds,
) -> StuckVerdict | None:
    """Repeated context-window errors (threshold 3 -- Northstar's number).

    The OpenHands document names the pattern ("repeated context window errors
    that indicate memory management issues") and gives no threshold.
    """
    hits = [
        event
        for event in events
        if event.kind == KIND_ERROR and _is_context_window_error(event.error_key[0])
    ]
    if len(hits) < thresholds.context_window_errors:
        return None
    return StuckVerdict(
        is_stuck=True,
        pattern=PATTERN_CONTEXT_WINDOW_ERRORS,
        summary=(
            f"{len(hits)} context-window errors (threshold "
            f"{thresholds.context_window_errors}; Northstar's threshold)"
        ),
        evidence=tuple({"error_key": list(event.error_key)} for event in hits),
        evidence_pointer=EvidencePointer(
            first_index=hits[0].index,
            last_index=hits[-1].index,
            count=len(hits),
        ),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class StuckDetector:
    """Detects repetition patterns in a Northstar session history.

    The detector is a **pure query**: ``is_stuck()`` reads the history it was
    given and returns a verdict.  It holds no counters that a call advances,
    it writes nothing, and it never halts a run.  What the caller does with
    the verdict -- stop the run, warn, or ignore -- is the caller's decision.

    Usage::

        detector = StuckDetector()
        verdict = detector.is_stuck(records)
        if verdict.is_stuck:
            ...  # the caller decides whether to stop
    """

    def __init__(self, thresholds: StuckThresholds | None = None) -> None:
        self.thresholds = thresholds or DEFAULT_THRESHOLDS

    # -- query ------------------------------------------------------------

    def is_stuck(self, records: Sequence[dict[str, Any]]) -> StuckVerdict:
        """Return the verdict for this history.  Does not change any state."""
        return self.detect(records)

    def detect(self, records: Sequence[dict[str, Any]]) -> StuckVerdict:
        """Run the five detectors over the history and return the first hit.

        The detectors run in the order the OpenHands document lists the
        patterns; the first one that trips is the verdict.  An empty history
        is not stuck and is not an error.
        """
        if not records:
            return StuckVerdict()
        events = _records_to_events(records)
        window = _window_events(events)
        if not window:
            return StuckVerdict()
        pairs = _build_pairs(window)
        for check in (
            lambda: _detect_repeat_action_observation(pairs, self.thresholds),
            lambda: _detect_repeat_action_error(pairs, self.thresholds),
            lambda: _detect_monologue(window, self.thresholds),
            lambda: _detect_alternating(pairs, self.thresholds),
            lambda: _detect_context_window_errors(window, self.thresholds),
        ):
            verdict = check()
            if verdict is not None:
                return verdict
        return StuckVerdict()

    # -- helpers ----------------------------------------------------------

    def normalised_events(self, records: Sequence[dict[str, Any]]) -> list[NormalizedEvent]:
        """The normalised events, exposed so a caller can inspect the keys."""
        return _records_to_events(records)


def detect(
    records: Sequence[dict[str, Any]],
    thresholds: StuckThresholds | None = None,
) -> StuckVerdict:
    """One-shot detection over a session history."""
    return StuckDetector(thresholds).detect(records)


def is_stuck(records: Sequence[dict[str, Any]]) -> bool:
    """True when the history trips one of the five patterns."""
    return detect(records).is_stuck
