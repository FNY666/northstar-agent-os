"""Condensation as a first-class log event: the view is derived from the log.

Source (Moltbook / OpenHands context condensation, rank 1; the taskbook quotes
the source text, which is the rule):

* Compression itself is **appended to the event log** as a first-class event:
  ``CondensationAction{forgotten: list[int], summary: str, summary_offset: int}``
  -- it records *which* event ids were forgotten, the summary text, and the
  position where the summary is inserted.
* ``View`` (``openhands/memory/view.py`` 13-93) derives the model-visible
  history *from the complete log*: drop the forgotten events, drop the
  condensation meta-events, and insert an ``AgentCondensationObservation`` at
  ``summary_offset``.
* Default three-stage pipeline (``openhands/server/session/session.py``
  187-214): ``ConversationWindowCondenser`` (answers an explicit condensation
  request) -> ``BrowserOutputCondenser`` (keeps only the most recent 2 browser
  observations, ``attention_window=2``) -> ``LLMSummarizingCondenser``
  (``keep_first=4, max_size=120``, summarising the middle events when over
  the limit).
* ``ContextWindowExceededError`` (``agent_controller.py`` 845-873) can
  trigger condensation reactively.
* Official self-report: cost per turn below half, SWE-bench subset 54% vs a
  53% baseline.  ("Cost below half" is a *self-report*, not a measurement.)

Honest attribution (must not be blurred):

* OpenHands does **not** score events by importance.  It condenses **by
  position** (keep the first 4 + keep the most recent window).  An
  importance-scored summary is a **Northstar extension**, not a borrowed
  mechanism.
* ``keep_first=4``, ``max_size=120``, ``attention_window=2`` and "54% vs 53%"
  are verbatim OpenHands numbers.  "Cost below half" is an official self-report.

What Northstar has today (read before designing this; see
``docs/design/event-condenser.md``):

* ``compaction.py`` cuts the transcript at a safe boundary and rewrites it **in
  place**.  The summarised history simply disappears from the model-visible
  transcript; **nothing is recorded in the log**.  Compression is therefore
  not auditable and not replayable.
* ``event_sourcing.py`` has a hash-chained append-only log with replay and
  snapshots, but no notion of condensation: a compacted-away event cannot be
  brought back.
* ``summarization_guard.py`` only checks a summary length ratio.
* No per-source throttling (the ``BrowserOutputCondenser`` shape) and no
  reactive over-limit trigger exist.

This module adds the missing piece without touching any existing module:
condensation is an event in the log, and the model-visible view is *derived*
from the log.  The log is never rewritten in place, so a replay reproduces the
view exactly, and every condensation stays auditable.

House style: frozen dataclasses, no wall clock, fail-closed validation,
stdlib-only, deterministic, version and schema pins, ``main()`` self-check.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

VERSION = "event-condenser.v1"
SCHEMA_PIN = "northstar.event_condenser/v1"

# --- verbatim OpenHands numbers (source text) --------------------------------
# LLMSummarizingCondenser(keep_first=4, max_size=120)
KEEP_FIRST = 4
MAX_SIZE = 120
# BrowserOutputCondenser(attention_window=2)
ATTENTION_WINDOW = 2

# The type of the meta-event that marks a condensation in the log.
CONDENSATION_EVENT_TYPE = "condensation"
# The type of the observation that the derived view shows in place of a
# forgotten run of events.
CONDENSATION_OBSERVATION_TYPE = "agent_condensation_observation"


class EventCondenserError(Exception):
    """Base class for every failure this module raises."""


class InvalidCondensationError(EventCondenserError):
    """A condensation event is malformed (bad types, bad offset, empty set)."""


class DuplicateCondensationError(EventCondenserError):
    """An event id was already forgotten by an earlier condensation.

    Rule (written down, not derived from the source): forgetting is
    **idempotent-refusing**.  A second condensation that names an already
    forgotten id is refused rather than silently ignored, because a silent
    no-op would hide a caller bug that believes it removed something twice.
    """


class ViewDerivationError(EventCondenserError):
    """The view could not be derived (offset out of range, unknown id)."""


class ContextStillExceededError(EventCondenserError):
    """The retry after a reactive condensation still exceeded the limit.

    Raised instead of dropping data silently.
    """


@dataclass(frozen=True)
class CondensationEvent:
    """One condensation, as a first-class log event.

    ``forgotten`` -- the ids of the events this condensation removes from the
    derived view.
    ``summary``    -- the summary text that replaces them.
    ``summary_offset`` -- the index in the derived view where the summary
    observation is inserted.

    The dataclass is frozen: a condensation is a fact about the log, not a
    mutable handle.
    """

    forgotten: tuple[int, ...]
    summary: str
    summary_offset: int

    def __init__(self, forgotten: object, summary: object,
                 summary_offset: object) -> None:
        if isinstance(forgotten, (str, bytes)) or not isinstance(forgotten, Iterable):
            raise InvalidCondensationError(
                f"forgotten must be an iterable of event ids, got {type(forgotten).__name__}")
        ids: list[int] = []
        for raw in forgotten:
            if isinstance(raw, bool) or not isinstance(raw, int):
                raise InvalidCondensationError(
                    f"forgotten ids must be ints, got {raw!r}")
            if raw in ids:
                raise InvalidCondensationError(
                    f"forgotten lists an id twice: {raw}")
            ids.append(raw)
        if not ids:
            raise InvalidCondensationError(
                "forgotten must not be empty: a condensation that forgets "
                "nothing is not a condensation")
        if not isinstance(summary, str):
            raise InvalidCondensationError(
                f"summary must be a str, got {type(summary).__name__}")
        if isinstance(summary_offset, bool) or not isinstance(summary_offset, int):
            raise InvalidCondensationError(
                f"summary_offset must be an int, got {summary_offset!r}")
        # A negative offset is *not* refused here: it is refused when the
        # view is derived.  Keeping the check at derivation time means the
        # log records what the caller asked for, and the refusal happens
        # where a wrong view would otherwise be handed out.
        object.__setattr__(self, "forgotten", tuple(ids))
        object.__setattr__(self, "summary", summary)
        object.__setattr__(self, "summary_offset", summary_offset)

    def as_dict(self) -> dict[str, Any]:
        """JSON-safe view with the schema pin."""
        return {
            "schema": SCHEMA_PIN,
            "event_type": CONDENSATION_EVENT_TYPE,
            "forgotten": list(self.forgotten),
            "summary": self.summary,
            "summary_offset": self.summary_offset,
        }


@dataclass(frozen=True)
class CondensationObservation:
    """The model-visible stand-in for a forgotten run of events."""

    summary: str
    summary_offset: int
    forgotten: tuple[int, ...] = field(default=())

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "observation_type": CONDENSATION_OBSERVATION_TYPE,
            "summary": self.summary,
            "summary_offset": self.summary_offset,
            "forgotten": list(self.forgotten),
        }


# --- the log ---------------------------------------------------------------
# The log is a list of records.  A normal record is a dict:
#   {"id": int, "type": "event", "source": str, "payload": Any}
# A condensation is a *meta* record appended to the same log:
#   {"id": int, "type": "condensation", "forgotten": [...], "summary": str,
#    "summary_offset": int}
# The log is append-only: nothing here ever rewrites or deletes a record.


def new_log() -> list[dict[str, Any]]:
    """An empty log."""
    return []


def append_event(log: list[dict[str, Any]], event_id: int, source: str,
                 payload: Any) -> dict[str, Any]:
    """Append one ordinary event; returns the record that was appended."""
    if isinstance(event_id, bool) or not isinstance(event_id, int):
        raise InvalidCondensationError(
            f"event id must be an int, got {event_id!r}")
    if not isinstance(source, str) or not source:
        raise InvalidCondensationError(
            f"event source must be a non-empty str, got {source!r}")
    for record in log:
        if record.get("id") == event_id:
            raise InvalidCondensationError(
                f"event id {event_id} is already in the log")
    record = {
        "id": event_id,
        "type": "event",
        "source": source,
        "payload": payload,
    }
    log.append(record)
    return record


def _forgotten_ids(log: Sequence[Mapping[str, Any]]) -> set[int]:
    """Ids already forgotten by a condensation in this log."""
    forgotten: set[int] = set()
    for record in log:
        if record.get("type") == CONDENSATION_EVENT_TYPE:
            for raw in record.get("forgotten", ()):  # type: ignore[union-attr]
                forgotten.add(int(raw))
    return forgotten


def _base_view(log: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The ordinary events of the log that no condensation has forgotten."""
    forgotten = _forgotten_ids(log)
    base: list[Mapping[str, Any]] = []
    for record in log:
        if record.get("type") == CONDENSATION_EVENT_TYPE:
            continue
        if int(record.get("id", -1)) in forgotten:
            continue
        base.append(record)
    return base


def _view_events(view: Sequence[Any]) -> list[Mapping[str, Any]]:
    """The ordinary event records inside a derived view, in view order."""
    return [item for item in view
            if isinstance(item, Mapping) and item.get("type") == "event"]


def _condensations(log: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The condensation meta-records, in log order."""
    return [r for r in log if r.get("type") == CONDENSATION_EVENT_TYPE]


# --- append ------------------------------------------------------------------


def append_condensation(log: list[dict[str, Any]], forgotten: Sequence[int],
                        summary: str, offset: int) -> CondensationEvent:
    """Append a condensation to the log; the log is never rewritten in place.

    The condensation becomes one more record in the log.  Every earlier record
    is left byte-for-byte untouched: the history stays replayable, and the
    condensation itself is auditable.

    Rule (see :class:`DuplicateCondensationError`): forgetting is
    **idempotent-refusing**.  Naming an id that an earlier condensation
    already forgot raises ``DuplicateCondensationError``; the log is left
    unchanged.
    """
    event = CondensationEvent(forgotten, summary, offset)
    already = _forgotten_ids(log)
    clash = already.intersection(event.forgotten)
    if clash:
        raise DuplicateCondensationError(
            "these event ids were already forgotten by an earlier "
            f"condensation: {sorted(clash)}")
    known = {int(r.get("id", -1)) for r in log
             if r.get("type") != CONDENSATION_EVENT_TYPE}
    unknown = [i for i in event.forgotten if i not in known]
    if unknown:
        raise InvalidCondensationError(
            f"cannot forget event ids that are not in the log: {unknown}")
    record = {
        "id": _next_condensation_id(log),
        "type": CONDENSATION_EVENT_TYPE,
        "forgotten": list(event.forgotten),
        "summary": event.summary,
        "summary_offset": event.summary_offset,
    }
    log.append(record)
    return event


def _next_condensation_id(log: Sequence[Mapping[str, Any]]) -> int:
    """A fresh id for the condensation record itself.

    Ids live in the same namespace as event ids, so the condensation record
    gets the next free one.  That keeps the log a single ordered id space.
    """
    used = {int(r.get("id", -1)) for r in log}
    candidate = 0
    while candidate in used:
        candidate += 1
    return candidate


# --- derive the view ---------------------------------------------------------


def derive_view(log: Sequence[Mapping[str, Any]]) -> list[Any]:
    """Derive the model-visible view from the complete log.

    Rules, in order:

    1. Events forgotten by a condensation are not in the view.
    2. Condensation meta-events are not in the view.
    3. The summary observation is inserted at ``summary_offset``.

    Fail-closed behaviour (written down, not taken from the source): a
    ``summary_offset`` outside ``[0, len(view)]`` raises
    ``ViewDerivationError``.  The view is never silently truncated or padded
    to fit an out-of-range offset -- a bad offset means the log and the
    condensation disagree, and a caller that cannot see that disagreement
    would act on a wrong view.

    Several condensations are replayed **in log order**: each one is applied
    to the view the earlier ones produced, so the view is what a replay of
    the log yields.
    """
    forgotten = _forgotten_ids(log)
    view: list[Any] = []
    for record in log:
        kind = record.get("type")
        if kind == CONDENSATION_EVENT_TYPE:
            offset = int(record.get("summary_offset", 0))
            if offset < 0 or offset > len(view):
                raise ViewDerivationError(
                    f"summary_offset {offset} is out of range for a view of "
                    f"{len(view)} item(s)")
            observation = CondensationObservation(
                summary=str(record.get("summary", "")),
                summary_offset=offset,
                forgotten=tuple(int(i) for i in record.get("forgotten", ())),  # type: ignore[arg-type]
            )
            view.insert(offset, observation)
            continue
        if int(record.get("id", -1)) in forgotten:
            continue
        view.append(record)
    return view


def replay(log: Sequence[Mapping[str, Any]]) -> list[Any]:
    """Replay the log into the view.

    Same function as :func:`derive_view`, named for the audit path: replaying
    a log that was never rewritten reproduces the same view byte for byte.
    """
    return derive_view(log)


def audit_condensations(log: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """List every condensation in the log with its forgotten set and summary.

    This is the audit view: for each condensation, which events it removed
    and what text replaced them.
    """
    audit: list[dict[str, Any]] = []
    for record in _condensations(log):
        audit.append({
            "id": int(record.get("id", -1)),
            "forgotten": [int(i) for i in record.get("forgotten", ())],  # type: ignore[arg-type]
            "summary": str(record.get("summary", "")),
            "summary_offset": int(record.get("summary_offset", 0)),
        })
    return audit


# --- throttle by source ------------------------------------------------------
# Verbatim source number: BrowserOutputCondenser(attention_window=2) -- keep
# only the most recent 2 browser observations.


def _source_events(log: Sequence[Mapping[str, Any]],
                   source: str) -> list[Mapping[str, Any]]:
    """Ordinary events of ``source`` that no condensation has forgotten.

    Already-forgotten events are excluded: the throttle decides what to drop
    from the *view*, and a forgotten event is not in the view any more.
    """
    forgotten = _forgotten_ids(log)
    return [r for r in log
            if r.get("type") != CONDENSATION_EVENT_TYPE
            and r.get("source") == source
            and int(r.get("id", -1)) not in forgotten]


def throttle_by_source(log: list[dict[str, Any]], source: str,
                       keep_last: int = ATTENTION_WINDOW) -> CondensationEvent | None:
    """Keep only the most recent ``keep_last`` events of one source.

    This is the ``BrowserOutputCondenser`` shape: browser/tool output
    observations are noisy and repetitive, so only the last few are kept.
    ``keep_last`` defaults to 2 -- the verbatim OpenHands ``attention_window``.

    The throttled-away events are **not** deleted.  A condensation event is
    appended that names them, exactly like any other condensation, so the log
    stays replayable and the throttle is auditable.

    Events from other sources are untouched: the throttle is per source.

    Returns the appended ``CondensationEvent``, or ``None`` when the source
    already has ``keep_last`` or fewer events (nothing to throttle).
    """
    if not isinstance(source, str) or not source:
        raise InvalidCondensationError(
            f"source must be a non-empty str, got {source!r}")
    if isinstance(keep_last, bool) or not isinstance(keep_last, int):
        raise InvalidCondensationError(
            f"keep_last must be an int, got {keep_last!r}")
    if keep_last < 0:
        raise InvalidCondensationError(
            f"keep_last must not be negative: {keep_last}")
    source_events = _source_events(log, source)
    if len(source_events) <= keep_last:
        return None
    forgotten = [int(r["id"]) for r in source_events[:-keep_last]] if keep_last else \
        [int(r["id"]) for r in source_events]
    offset = _position_in_view(log, forgotten[0])
    summary = (
        f"[Throttled {len(forgotten)} observation(s) from source {source!r}; "
        f"kept the most recent {keep_last}.]")
    return append_condensation(log, forgotten, summary, offset)


def _position_in_view(log: Sequence[Mapping[str, Any]], event_id: int) -> int:
    """The index of ``event_id`` in the view the log currently derives."""
    view = derive_view(log)
    for index, item in enumerate(view):
        if isinstance(item, Mapping) and int(item.get("id", -1)) == event_id:
            return index
    raise ViewDerivationError(
        f"event id {event_id} is not in the current view")


# --- reactive condensation on a context-limit signal --------------------------
# Verbatim source number: LLMSummarizingCondenser(keep_first=4, max_size=120)
# summarises the *middle* events; the first 4 are kept.

KEEP_RECENT = 2  # Northstar choice; the source quote does not pin this number.


def _extractive_summary(events: Sequence[Mapping[str, Any]]) -> str:
    """A deterministic, provider-free summary of the forgotten events.

    No model call: condensation must not cost budget and must be
    reproducible.  The summary names each forgotten event's source and a
    clipped snippet of its payload, so the model still sees what kind of
    thing happened even though the raw event is gone.
    """
    lines = ["[Earlier events summarised by the event condenser]"]
    for record in events:
        source = str(record.get("source", "?"))
        payload = record.get("payload")
        text = " ".join(str(payload).split())
        if len(text) > 160:
            text = text[:157] + "..."
        lines.append(f"- event {int(record.get('id', -1))} [{source}]: {text}")
    return "\n".join(lines)


def condense_on_limit(
    log: list[dict[str, Any]],
    *,
    is_exceeded: Callable[[Sequence[Any]], bool],
    keep_first: int = KEEP_FIRST,
    keep_recent: int = KEEP_RECENT,
    summarizer: Callable[[Sequence[Mapping[str, Any]]], str] | None = None,
) -> CondensationEvent | None:
    """React to a context-limit signal: condense the middle, retry once.

    This is the ``ContextWindowExceededError`` path: when the caller's check
    says the view still exceeds the context limit, the middle events are
    condensed (the first ``keep_first`` events are kept verbatim, the most
    recent ``keep_recent`` are kept verbatim, the middle is summarised), and
    the caller's check runs **once** more on the derived view.

    * No signal (not exceeded) -> ``None``, nothing is appended.
    * Signal, middle condensed, retry says it fits -> the ``CondensationEvent``
      that was appended.
    * Signal, retry still exceeded -> ``ContextStillExceededError``.  The
      error is explicit: data is never dropped silently.  The condensation
      that was appended stays in the log (it is a fact), and the error names
      what was forgotten so the caller can decide what to do.
    * Signal but nothing can be condensed (the log is shorter than
      ``keep_first + keep_recent``) -> ``ContextStillExceededError`` too.
    """
    if not callable(is_exceeded):
        raise InvalidCondensationError(
            "is_exceeded must be callable")
    if isinstance(keep_first, bool) or not isinstance(keep_first, int) or keep_first < 0:
        raise InvalidCondensationError(
            f"keep_first must be a non-negative int, got {keep_first!r}")
    if isinstance(keep_recent, bool) or not isinstance(keep_recent, int) or keep_recent < 0:
        raise InvalidCondensationError(
            f"keep_recent must be a non-negative int, got {keep_recent!r}")

    view = derive_view(log)
    if not is_exceeded(view):
        return None
    base = _base_view(log)
    # The head (keep_first) and the recent window (keep_recent) are kept
    # verbatim; only the middle between them can be condensed.
    keep = min(keep_first + keep_recent, len(base))
    if keep >= len(base):
        raise ContextStillExceededError(
            f"context still exceeded and nothing can be condensed: the log "
            f"holds {len(base)} event(s), the head ({keep_first}) and the "
            f"recent window ({keep_recent}) already cover it")
    middle = base[keep_first:len(base) - keep_recent]
    if not middle:
        raise ContextStillExceededError(
            "context still exceeded and the middle span is empty")
    forgotten = [int(r["id"]) for r in middle]
    offset = _position_in_view(log, forgotten[0])
    if summarizer is None:
        summary = _extractive_summary(middle)
    else:
        written = str(summarizer(middle) or "").strip()
        # An empty summary would silently delete the middle; the extractive
        # fallback takes over and says so in the text.
        summary = written or _extractive_summary(middle)
    event = append_condensation(log, forgotten, summary, offset)
    retry_view = derive_view(log)
    if is_exceeded(retry_view):
        raise ContextStillExceededError(
            f"context still exceeded after one condensation: "
            f"{len(retry_view)} item(s) in the view, forgotten "
            f"{forgotten}; the data is still in the log")
    return event


# --- Northstar extension: importance-scored condensation ----------------------
# EXTENSION, NOT SOURCE TEXT.  OpenHands does not score events by importance;
# it condenses **by position** (keep the first 4 + keep the recent window).
# The default behaviour of this module is positional, exactly like the source.
# The scoring interface below exists so a Northstar host *may* choose which
# events to condense; it is opt-in and never used by default.


def condense_by_importance(
    log: list[dict[str, Any]],
    scorer: Callable[[Mapping[str, Any]], float],
    *,
    keep: int,
    summary: str | None = None,
    summary_offset: int | None = None,
) -> CondensationEvent | None:
    """Condense the *least important* events (Northstar extension).

    ``scorer`` maps an event record to a score; the ``keep`` highest-scoring
    events stay, the rest are condensed.  The scorer is the caller's, so the
    ranking is explicit and auditable rather than hidden in the runtime.

    This is **not** the default path: :func:`condense_on_limit` and
    :func:`throttle_by_source` are positional, matching the source.
    """
    if not callable(scorer):
        raise InvalidCondensationError("scorer must be callable")
    if isinstance(keep, bool) or not isinstance(keep, int) or keep < 0:
        raise InvalidCondensationError(
            f"keep must be a non-negative int, got {keep!r}")
    base = _base_view(log)
    if len(base) <= keep:
        return None
    scored = sorted(
        base,
        key=lambda record: (float(scorer(record)), -int(record.get("id", 0))),
    )
    forgotten_records = scored[:len(base) - keep]
    forgotten = [int(r["id"]) for r in forgotten_records]
    offset = _position_in_view(log, forgotten[0]) if summary_offset is None \
        else summary_offset
    text = summary if summary is not None else _extractive_summary(forgotten_records)
    return append_condensation(log, forgotten, text, offset)


def main() -> None:
    """Self-check: the three paths the module exists for."""
    log = new_log()
    for index in range(6):
        append_event(log, index, "browser" if index < 4 else "user",
                     f"payload {index}")
    before = [dict(record) for record in log]
    event = append_condensation(log, [1, 2], "two browser events folded", 1)
    assert event.forgotten == (1, 2)
    assert log[:6] == before, "the log must not be rewritten in place"
    view = derive_view(log)
    assert isinstance(view[1], CondensationObservation)
    assert 1 not in [v.get("id") for v in view if isinstance(v, Mapping)]
    assert replay(log) == view
    assert audit_condensations(log)[0]["forgotten"] == [1, 2]
    # The throttle works on what is still in the view: 1 and 2 are already
    # forgotten, so only 0 and 3 remain -- nothing left to throttle.
    assert throttle_by_source(log, "browser", keep_last=2) is None
    fresh = new_log()
    for index in range(5):
        append_event(fresh, index, "browser", f"payload {index}")
    throttled = throttle_by_source(fresh, "browser", keep_last=2)
    assert throttled is not None and throttled.forgotten == (0, 1, 2)
    print("event-condenser OK")


if __name__ == "__main__":
    main()
