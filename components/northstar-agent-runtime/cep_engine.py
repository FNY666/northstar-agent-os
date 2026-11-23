"""Complex event processing: sequence-pattern matching over event streams.

A complex event is a *pattern* of primitive events in order: "a login,
then an action, within 100 sequence numbers". :class:`CEPEngine` pins
such patterns and scans host-reported event streams for matches,
deterministically and without a wall-clock -- ordering and span are
measured in caller-supplied logical sequence numbers, never time.

Patterns:

* ``define_pattern(name, stages)`` registers a named ordered sequence of
  *stages*. A stage is a predicate over one event and may be given as:

  - a callable ``event -> bool`` (must return a real ``bool``; anything
    else is refused fail-closed at match time),
  - a ``str`` meaning "the event's ``type`` attribute equals this",
  - a ``mapping`` of attribute equalities (every listed key must equal
    the listed value in the event).

* ``within(pattern_name, max_span)`` bounds the logical distance
  between the first and last event of a match (``max_span >= 0``); a
  candidate that would take longer is not a match. Unset by default
  (no bound); ``within(name, None)`` clears a bound.

* ``match(pattern_name, events)`` scans a stream of events (mappings
  with an int ``seq``; seqs must strictly increase) and returns a tuple
  of frozen :class:`PatternMatch` records, using the standard
  *skip-till-next-match* selection strategy with an anchored first
  stage: the first stage must match at the start position itself,
  later stages take their earliest completion from there, and scanning
  resumes at the next position after the match's first event. Every
  run over the same inputs produces the same matches -- replays are
  exact.

Matching pins digests, not payloads: each event contributes a
``sha256:`` digest of its canonical body to the match record, so the
audit trail carries pins, never raw event contents.

Honest scope: this is single-host pattern matching over *reported*
events, not a stream processor -- no windows over time, no retractions,
no out-of-order tolerance, no distribution. A match proves "these
reported events fit the pattern", never that the underlying activity
really happened in that order; a host that fabricates events fabricates
matches. ``within`` bounds logical seq distance, not elapsed time.
State is in-memory; persistence is the host's job.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


#: Version pin for this module's record shape.
CEP_ENGINE_VERSION = "cep-engine.v1"

#: Schema pin carried on audit records.
CEP_ENGINE_SCHEMA = "northstar.cep-engine.v1"

#: Guardrail: most stages a single pattern may declare.
_MAX_STAGES = 64

#: Guardrail: most events a single match() call will scan.
_MAX_EVENTS = 1_000_000

#: Guardrail: most patterns one engine will hold.
_MAX_PATTERNS = 10_000

#: Fixed audit vocabulary for cep_audit_event().
_AUDIT_KINDS = ("pattern-defined", "within-set", "matched", "scan-complete")


class CEPEngineError(Exception):
    """Base error for cep-engine failures."""


class DuplicatePatternError(CEPEngineError):
    """Raised when defining a pattern name that already exists."""


class UnknownPatternError(CEPEngineError):
    """Raised when referencing a pattern that was never defined."""


class PatternError(CEPEngineError):
    """Raised when a pattern, stage, or predicate is malformed."""


class EventError(CEPEngineError):
    """Raised when an event is malformed."""


def _check_name(name: Any, what: str = "pattern name") -> str:
    if isinstance(name, bool) or not isinstance(name, str) or not name:
        raise PatternError(f"{what} must be a non-empty str, got {name!r}")
    return name


def _check_seq(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EventError(f"{what} must be a non-negative int, got {value!r}")
    return value


def _canonical(value: Any) -> bytes:
    """Deterministic, type-tagged canonical encoding for digest pins.

    ``"1"`` (str), ``1`` (int) and ``b"1"`` (bytes) encode differently,
    so a type confusion can never make two different events pin the
    same. NaN/inf, non-str dict keys and integral floats beyond 2**53
    are refused fail-closed (the JCS precision-loss caveat documented
    in ``secure_aggregation``).
    """
    if isinstance(value, bool):
        return b"b" + (b"1" if value else b"0")
    if isinstance(value, int):
        return b"i" + str(value).encode("ascii")
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise EventError("NaN/inf are not digest-pinnable")
        if value.is_integer() and abs(value) > 2**53:
            raise EventError("integral float beyond 2**53 loses precision")
        return b"f" + repr(value).encode("ascii")
    if isinstance(value, str):
        return b"s" + value.encode("utf-8")
    if isinstance(value, bytes):
        return b"y" + value
    if value is None:
        return b"n"
    if isinstance(value, (list, tuple)):
        parts = b"".join(b"e" + _canonical(v) for v in value)
        return b"[" + parts + b"]"
    if isinstance(value, Mapping):
        for key in value:
            if isinstance(key, bool) or not isinstance(key, str):
                raise EventError("mapping keys must be non-bool str")
        items = sorted(value.items(), key=lambda kv: kv[0])
        parts = b"".join(b"k" + _canonical(k) + b"v" + _canonical(v) for k, v in items)
        return b"{" + parts + b"}"
    raise EventError(f"not digest-pinnable: {type(value).__name__}")


def _pin(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _validate_stage(stage: Any, index: int) -> None:
    if callable(stage):
        return
    if isinstance(stage, str):
        if not stage:
            raise PatternError(f"stage {index}: empty type string")
        return
    if isinstance(stage, Mapping):
        if not stage:
            raise PatternError(f"stage {index}: empty attribute mapping")
        for key in stage:
            if isinstance(key, bool) or not isinstance(key, str) or not key:
                raise PatternError(f"stage {index}: bad attribute key {key!r}")
        return
    raise PatternError(
        f"stage {index}: must be a callable, a type str, or an attribute mapping, "
        f"got {type(stage).__name__}"
    )


def _stage_matches(stage: Any, event: Mapping[str, Any]) -> bool:
    """Test one event against one stage; fail-closed on bad predicates."""
    if callable(stage):
        verdict = stage(event)
        if not isinstance(verdict, bool):
            raise PatternError(
                f"stage predicate must return bool, returned {type(verdict).__name__}"
            )
        return verdict
    if isinstance(stage, str):
        return event.get("type") == stage
    # attribute-equality mapping
    for key, want in stage.items():
        if key not in event or event[key] != want:
            return False
    return True


@dataclass(frozen=True)
class Pattern:
    """Frozen record of a defined pattern."""

    name: str
    stage_count: int
    max_span: int | None
    digest: str
    schema: str = CEP_ENGINE_SCHEMA
    version: str = CEP_ENGINE_VERSION

    def __post_init__(self) -> None:
        _check_name(self.name)
        if isinstance(self.stage_count, bool) or not isinstance(self.stage_count, int):
            raise PatternError("stage_count must be an int")
        if not 1 <= self.stage_count <= _MAX_STAGES:
            raise PatternError("stage_count out of range")
        if self.max_span is not None:
            if isinstance(self.max_span, bool) or not isinstance(self.max_span, int):
                raise PatternError("max_span must be a non-negative int or None")
            if self.max_span < 0:
                raise PatternError("max_span must be non-negative")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise PatternError("digest must be a sha256: pin")

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "stage_count": self.stage_count,
            "max_span": self.max_span,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }


@dataclass(frozen=True)
class PatternMatch:
    """Frozen record of one pattern match over a stream."""

    pattern: str
    event_seqs: tuple
    start_seq: int
    end_seq: int
    span: int
    event_digests: tuple
    digest: str
    schema: str = CEP_ENGINE_SCHEMA
    version: str = CEP_ENGINE_VERSION

    def __post_init__(self) -> None:
        _check_name(self.pattern)
        if not isinstance(self.event_seqs, tuple) or len(self.event_seqs) < 1:
            raise PatternError("event_seqs must be a non-empty tuple")
        for seq in self.event_seqs:
            _check_seq(seq, "event seq")
        if list(self.event_seqs) != sorted(self.event_seqs):
            raise PatternError("event_seqs must be increasing")
        if len(set(self.event_seqs)) != len(self.event_seqs):
            raise PatternError("event_seqs must be distinct")
        _check_seq(self.start_seq, "start_seq")
        _check_seq(self.end_seq, "end_seq")
        if self.start_seq != self.event_seqs[0] or self.end_seq != self.event_seqs[-1]:
            raise PatternError("start/end must bound the matched seqs")
        if self.span != self.end_seq - self.start_seq:
            raise PatternError("span must equal end_seq - start_seq")
        if not isinstance(self.event_digests, tuple):
            raise PatternError("event_digests must be a tuple")
        if len(self.event_digests) != len(self.event_seqs):
            raise PatternError("event_digests must align with event_seqs")
        for digest in self.event_digests:
            if not isinstance(digest, str) or not digest.startswith("sha256:"):
                raise PatternError("event digests must be sha256: pins")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise PatternError("digest must be a sha256: pin")

    def as_dict(self) -> dict:
        return {
            "pattern": self.pattern,
            "event_seqs": list(self.event_seqs),
            "start_seq": self.start_seq,
            "end_seq": self.end_seq,
            "span": self.span,
            "event_digests": list(self.event_digests),
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }


def _stage_fingerprint(stage: Any) -> str:
    """A stable, non-executing fingerprint of a stage for the pattern digest."""
    if callable(stage):
        name = getattr(stage, "__name__", None) or type(stage).__name__
        return f"callable:{name}"
    if isinstance(stage, str):
        return f"type:{stage}"
    return "attrs:" + json.dumps(
        {k: repr(v) for k, v in sorted(stage.items())}, sort_keys=True
    )


class CEPEngine:
    """Deterministic complex-event pattern matcher over logical seqs."""

    def __init__(self) -> None:
        self._patterns: dict[str, tuple[tuple, int | None]] = {}

    # -- pattern definition -------------------------------------------------

    def define_pattern(self, name: str, stages: Sequence[Any]) -> Pattern:
        """Register ``name`` as an ordered sequence of ``stages``.

        Redefining an existing name is refused fail-closed
        (:class:`DuplicatePatternError`) -- patterns are immutable once
        defined; make a new engine instead.
        """
        name = _check_name(name)
        if name in self._patterns:
            raise DuplicatePatternError(f"pattern {name!r} already defined")
        if len(self._patterns) >= _MAX_PATTERNS:
            raise PatternError("too many patterns in this engine")
        if not isinstance(stages, Sequence) or isinstance(stages, (str, bytes, Mapping)):
            raise PatternError("stages must be a non-empty sequence of stages")
        stages = tuple(stages)
        if not 1 <= len(stages) <= _MAX_STAGES:
            raise PatternError(f"a pattern needs 1..{_MAX_STAGES} stages")
        for index, stage in enumerate(stages):
            _validate_stage(stage, index)
        digest = _pin(
            {
                "cep-pattern": True,
                "name": name,
                "stages": [_stage_fingerprint(s) for s in stages],
            }
        )
        self._patterns[name] = (stages, None)
        return Pattern(name=name, stage_count=len(stages), max_span=None, digest=digest)

    def within(self, pattern_name: str, max_span: int | None) -> Pattern:
        """Bound the logical span of ``pattern_name`` matches.

        ``max_span`` is a non-negative int in seq units; ``None`` clears
        a bound. A match whose ``end_seq - start_seq`` exceeds the bound
        is not reported.
        """
        pattern_name = _check_name(pattern_name, "pattern name")
        if pattern_name not in self._patterns:
            raise UnknownPatternError(f"unknown pattern {pattern_name!r}")
        if max_span is not None:
            if isinstance(max_span, bool) or not isinstance(max_span, int):
                raise PatternError(f"max_span must be a non-negative int or None, got {max_span!r}")
            if max_span < 0:
                raise PatternError("max_span must be non-negative")
        stages, _old = self._patterns[pattern_name]
        self._patterns[pattern_name] = (stages, max_span)
        digest = _pin(
            {
                "cep-pattern": True,
                "name": pattern_name,
                "stages": [_stage_fingerprint(s) for s in stages],
            }
        )
        return Pattern(
            name=pattern_name, stage_count=len(stages), max_span=max_span, digest=digest
        )

    def pattern(self, name: str) -> Pattern:
        """Return the frozen record for a defined pattern."""
        name = _check_name(name)
        if name not in self._patterns:
            raise UnknownPatternError(f"unknown pattern {name!r}")
        stages, max_span = self._patterns[name]
        digest = _pin(
            {
                "cep-pattern": True,
                "name": name,
                "stages": [_stage_fingerprint(s) for s in stages],
            }
        )
        return Pattern(name=name, stage_count=len(stages), max_span=max_span, digest=digest)

    def patterns(self) -> tuple:
        """Names of all defined patterns, in definition order."""
        return tuple(self._patterns)

    # -- matching -----------------------------------------------------------

    def _checked_events(self, events: Any) -> tuple:
        if not isinstance(events, Sequence) or isinstance(events, (str, bytes, Mapping)):
            raise EventError("events must be a sequence of event mappings")
        events = tuple(events)
        if len(events) > _MAX_EVENTS:
            raise EventError("too many events in one match() call")
        prev = None
        for index, event in enumerate(events):
            if not isinstance(event, Mapping):
                raise EventError(f"event {index}: must be a mapping, got {type(event).__name__}")
            if "seq" not in event:
                raise EventError(f"event {index}: missing 'seq'")
            seq = event["seq"]
            _check_seq(seq, f"event {index} seq")
            if prev is not None and seq <= prev:
                raise EventError(f"event {index}: seqs must strictly increase")
            prev = seq
            _pin(event)  # fail-closed now: non-pinnable payloads refuse early
        return events

    def match(self, pattern_name: str, events: Sequence[Mapping[str, Any]]) -> tuple:
        """Scan ``events`` for ``pattern_name``; return frozen matches.

        Selection strategy is skip-till-next-match with an anchored
        first stage: the first stage must match at the start position
        itself, later stages take their earliest completion from there,
        and scanning then resumes at the next position after the
        match's first event. A start whose earliest completion exceeds
        the ``within`` bound yields no match from that position.
        """
        pattern_name = _check_name(pattern_name, "pattern name")
        if pattern_name not in self._patterns:
            raise UnknownPatternError(f"unknown pattern {pattern_name!r}")
        events = self._checked_events(events)
        stages, max_span = self._patterns[pattern_name]
        n_stages = len(stages)
        matches: list[PatternMatch] = []
        digests = [_pin(event) for event in events]
        start = 0
        while start < len(events):
            if not _stage_matches(stages[0], events[start]):
                start += 1
                continue
            matched_positions = [start]
            pos = start + 1
            for stage in stages[1:]:
                found = None
                while pos < len(events):
                    if _stage_matches(stage, events[pos]):
                        found = pos
                        break
                    pos += 1
                if found is None:
                    break
                matched_positions.append(found)
                pos = found + 1
            if len(matched_positions) == n_stages:
                seqs_t = tuple(events[p]["seq"] for p in matched_positions)
                first, last = seqs_t[0], seqs_t[-1]
                if max_span is None or last - first <= max_span:
                    matched_digests = tuple(digests[p] for p in matched_positions)
                    matches.append(
                        PatternMatch(
                            pattern=pattern_name,
                            event_seqs=seqs_t,
                            start_seq=seqs_t[0],
                            end_seq=seqs_t[-1],
                            span=seqs_t[-1] - seqs_t[0],
                            event_digests=matched_digests,
                            digest=_pin(
                                {
                                    "cep-match": True,
                                    "pattern": pattern_name,
                                    "event_seqs": list(seqs_t),
                                    "event_digests": list(matched_digests),
                                }
                            ),
                        )
                    )
            start += 1
        return tuple(matches)

    # -- audit ---------------------------------------------------------------

    def cep_audit_event(
        self, kind: str, seq: int, pattern: str | None = None
    ) -> dict:
        """Shape a CEP lifecycle event as an ``audit.ndjson/1`` record.

        ``kind`` is one of ``pattern-defined`` / ``within-set`` /
        ``matched`` / ``scan-complete``.
        """
        if kind not in _AUDIT_KINDS:
            raise ValueError(f"unknown audit kind {kind!r}")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ValueError("seq must be a non-negative int")
        if pattern is not None:
            _check_name(pattern, "pattern")
        return {
            "schema": "audit.ndjson/1",
            "kind": f"cep-engine.{kind}",
            "module": CEP_ENGINE_SCHEMA,
            "version": CEP_ENGINE_VERSION,
            "seq": seq,
            "pattern": pattern,
        }


def main() -> None:
    engine = CEPEngine()
    engine.define_pattern(
        "login-then-act",
        ["login", {"type": "action", "priv": "write"}],
    )
    engine.within("login-then-act", 50)
    events = [
        {"seq": 1, "type": "login", "user": "a"},
        {"seq": 2, "type": "heartbeat"},
        {"seq": 7, "type": "action", "priv": "write"},
        {"seq": 400, "type": "login", "user": "b"},
        {"seq": 500, "type": "action", "priv": "write"},
    ]
    matches = engine.match("login-then-act", events)
    assert len(matches) == 1
    assert matches[0].event_seqs == (1, 7)
    assert matches[0].span == 6
    # with the bound cleared, the second login->action pair also matches
    engine.within("login-then-act", None)
    matches2 = engine.match("login-then-act", events)
    assert len(matches2) == 2
    assert matches2[1].event_seqs == (400, 500)
    event = engine.cep_audit_event("matched", 3, pattern="login-then-act")
    assert event["schema"] == "audit.ndjson/1"
    print("cep-engine OK: define, within, match, audit")


if __name__ == "__main__":
    main()
