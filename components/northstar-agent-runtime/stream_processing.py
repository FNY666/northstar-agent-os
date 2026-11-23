"""Stream processing: tumbling/sliding windows, keyed joins, aggregates.

A ``StreamProcessing`` ledger books host-reported stream events and
applies Flink/Kafka-Streams-shaped windowing as a deterministic
single-host state machine:

- ``register_stream(stream_id, seq, key_fields=())`` pins a named stream.
  Events are host-reported ``(key, value, event_seq)`` triples; the
  module *books* them, it never pulls from a broker.
- ``ingest(stream_id, key, value, event_seq, seq)`` appends a frozen
  ``EventRecord`` (out-of-order ``event_seq`` is data, flagged
  ``late=True``; it is not dropped silently).
- ``window(window_id, stream_id, kind, size_seq, seq, slide_seq=None)``
  pins a window spec: ``tumbling`` (``slide`` defaults to ``size``) or
  ``sliding`` (``slide < size``). Time is logical-seq time: the
  assignment of events to window instances is computed purely from
  ``event_seq`` values, never the wall clock.
- ``aggregate(window_id, seq, function="count")`` → frozen
  ``AggregateResult`` over the events whose window instance closes at
  or before ``seq``. Pinned functions: ``count``/``sum``/``min``/``max``/``avg``.
  Non-numeric values are skipped for numeric functions (counted in
  ``skipped``), never coerced.
- ``join(join_id, left_window_id, right_window_id, seq, how="inner",
  tolerance_seq=0)`` → frozen ``JoinResult``: pairs buffered events from
  both windows whose keys are equal and whose ``event_seq`` values are
  within ``tolerance_seq``. ``inner`` keeps matched pairs only;
  ``left`` keeps unmatched left events as well (right side ``None``).
  Pair matching is deterministic: candidates sorted by digest.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``stream-processing.v1``, schema pin ``northstar.stream-processing.v1``,
``main()`` self-check.

Honest scope: this module books *declared* stream state and computes
window assignments from host-reported ``event_seq`` values. It cannot
observe a real broker, cannot prove event ordering across partitions,
cannot measure throughput or latency, and cannot detect events the host
never reports. An aggregate means "the host reported these events in
this window", never "the wire carried exactly this".
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
STREAM_PROCESSING_VERSION = "stream-processing.v1"

#: Schema pin carried by records and audit events.
STREAM_PROCESSING_SCHEMA = "northstar.stream-processing.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned window kinds.
KIND_TUMBLING = "tumbling"
KIND_SLIDING = "sliding"
WINDOW_KINDS = (KIND_TUMBLING, KIND_SLIDING)

#: Pinned aggregate functions.
AGGREGATE_FUNCTIONS = ("count", "sum", "min", "max", "avg")

#: Pinned join types.
JOIN_INNER = "inner"
JOIN_LEFT = "left"
JOIN_TYPES = (JOIN_INNER, JOIN_LEFT)

#: Pinned transform functions (Kafka Streams / Flink topology ops).
#: ``identity`` copies events unchanged; ``filter`` drops events whose
#: value mapping does not carry ``options["field"] == options["value"]``;
#: ``project`` keeps only ``options["fields"]`` of a mapping value.
TRANSFORM_IDENTITY = "identity"
TRANSFORM_FILTER = "filter"
TRANSFORM_PROJECT = "project"
TRANSFORM_FUNCTIONS = (
    TRANSFORM_IDENTITY, TRANSFORM_FILTER, TRANSFORM_PROJECT,
)

_GENESIS = "genesis"

#: Sentinel for transform functions that drop an event (filter no-match,
#: project on a non-mapping value). Module-private by design.
_DROP = object()


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class StreamProcessingError(ValueError):
    """Base for all stream-processing structural problems and refused transitions."""


class BadStreamError(StreamProcessingError):
    """Stream registration is malformed (bad id, key fields)."""


class DuplicateStreamError(StreamProcessingError):
    """A stream id is already registered."""


class UnknownStreamError(StreamProcessingError):
    """No stream is pinned for the requested id."""


class BadEventError(StreamProcessingError):
    """An ingested event is malformed."""


class BadWindowError(StreamProcessingError):
    """A window spec is malformed (bad kind, size, slide)."""


class DuplicateWindowError(StreamProcessingError):
    """A window id is already pinned."""


class UnknownWindowError(StreamProcessingError):
    """No window is pinned for the requested id."""


class BadAggregateError(StreamProcessingError):
    """The aggregate function name or target is malformed."""


class BadJoinError(StreamProcessingError):
    """A join spec is malformed (bad type, tolerance)."""


class DuplicateJoinError(StreamProcessingError):
    """A join id is already pinned."""


class UnknownJoinError(StreamProcessingError):
    """No join is pinned for the requested id."""


class SeqOrderError(StreamProcessingError):
    """Caller seq did not strictly increase."""


class AuditKindError(StreamProcessingError):
    """Unknown audit event kind."""


class BadTopologyError(StreamProcessingError):
    """Malformed source/sink/transform id or option."""


class DuplicateSourceError(StreamProcessingError):
    """Source id already bound."""


class UnknownSourceError(StreamProcessingError):
    """Source id not bound."""


class DuplicateSinkError(StreamProcessingError):
    """Sink id already bound."""


class UnknownSinkError(StreamProcessingError):
    """Sink id not bound."""


class BadTransformError(StreamProcessingError):
    """Malformed transform spec (function or options)."""


class DuplicateTransformError(StreamProcessingError):
    """Transform id already pinned."""


class UnknownTransformError(StreamProcessingError):
    """Transform id not pinned."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StreamProcessingError(f"{name} must be a non-empty string")
    return value.strip()


def _check_positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StreamProcessingError(f"{name} must be a positive int")
    return value


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([STREAM_PROCESSING_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _canon(value: Any) -> Any:
    """Canonicalize a key/value for digest purposes."""
    if isinstance(value, Mapping):
        return {str(k): _canon(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_canon(v) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float, str)):
        return value
    raise StreamProcessingError(
        f"value must be a JSON scalar/list/mapping, got {type(value).__name__}"
    )


def _window_instances(
    kind: str, size: int, slide: int, event_seq: int
) -> Tuple[int, ...]:
    """Window-instance start seqs that contain ``event_seq`` (logical-seq time).

    Windows are half-open ``[start, start + size)``. Tumbling windows
    partition the axis with ``slide == size``; sliding windows overlap.
    Deterministic and wall-clock free.
    """
    if kind == KIND_TUMBLING:
        return (event_seq // size * size,)
    # Sliding: candidate starts are k*slide for k such that
    # start <= event_seq < start + size, and start >= 0.
    first = max(0, (event_seq - size + 1 + slide - 1) // slide * slide)
    starts: List[int] = []
    k = first
    while k <= event_seq:
        if k <= event_seq < k + size:
            starts.append(k)
        k += slide
    return tuple(starts)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StreamRecord:
    """One pinned stream registration (frozen)."""

    stream_id: str
    key_fields: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = STREAM_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "stream", self.stream_id, list(self.key_fields), self.seq
        )


@dataclass(frozen=True)
class EventRecord:
    """One booked stream event (frozen).

    ``late`` is data: the event's ``event_seq`` went backwards relative to
    the stream's current watermark; it is booked, not dropped.
    """

    event_id: str
    stream_id: str
    key: Any
    value: Any
    event_seq: int
    late: bool
    seq: int
    digest: str
    schema: str = STREAM_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "event", self.event_id, self.stream_id, _canon(self.key),
            _canon(self.value), self.event_seq, self.late, self.seq,
        )


@dataclass(frozen=True)
class WindowRecord:
    """One pinned window spec (frozen)."""

    window_id: str
    stream_id: str
    kind: str
    size_seq: int
    slide_seq: int
    seq: int
    digest: str
    schema: str = STREAM_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "window", self.window_id, self.stream_id, self.kind,
            self.size_seq, self.slide_seq, self.seq,
        )


@dataclass(frozen=True)
class AggregateResult:
    """One window aggregation result (frozen)."""

    agg_id: str
    window_id: str
    function: str
    window_start: int
    window_end: int
    count: int
    skipped: int
    value: Any
    seq: int
    digest: str
    schema: str = STREAM_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "aggregate", self.agg_id, self.window_id, self.function,
            self.window_start, self.window_end, self.count, self.skipped,
            self.value, self.seq,
        )


@dataclass(frozen=True)
class JoinRecord:
    """One pinned join spec (frozen)."""

    join_id: str
    left_window_id: str
    right_window_id: str
    how: str
    tolerance_seq: int
    seq: int
    digest: str
    schema: str = STREAM_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "join", self.join_id, self.left_window_id, self.right_window_id,
            self.how, self.tolerance_seq, self.seq,
        )


@dataclass(frozen=True)
class JoinPair:
    """One matched join pair (frozen)."""

    left_event_id: Optional[str]
    right_event_id: Optional[str]
    key: Any
    seq: int
    digest: str
    schema: str = STREAM_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "pair", self.left_event_id, self.right_event_id,
            _canon(self.key), self.seq,
        )


@dataclass(frozen=True)
class JoinResult:
    """One join evaluation result (frozen)."""

    result_id: str
    join_id: str
    pairs: Tuple[JoinPair, ...]
    matched: int
    unmatched_left: int
    seq: int
    digest: str
    schema: str = STREAM_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "join-result", self.result_id, self.join_id,
            [p.digest for p in self.pairs], self.matched,
            self.unmatched_left, self.seq,
        )


@dataclass(frozen=True)
class SourceRecord:
    """One source connector pinned to a stream it feeds (frozen)."""

    source_id: str
    stream_id: str
    seq: int
    digest: str
    schema: str = STREAM_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "source", self.source_id, self.stream_id, self.seq
        )


@dataclass(frozen=True)
class SinkRecord:
    """One sink connector pinned to a stream it drains (frozen)."""

    sink_id: str
    stream_id: str
    seq: int
    digest: str
    schema: str = STREAM_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "sink", self.sink_id, self.stream_id, self.seq
        )


@dataclass(frozen=True)
class TransformRecord:
    """One topology edge pinned between two streams (frozen).

    ``options`` carries the pinned per-function configuration:
    ``identity`` -> (); ``filter`` -> (("field", name), ("value", canon));
    ``project`` -> (("fields", (name, ...)),).
    """

    transform_id: str
    input_stream_id: str
    output_stream_id: str
    function: str
    options: Tuple[Tuple[str, Any], ...]
    seq: int
    digest: str
    schema: str = STREAM_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "transform", self.transform_id, self.input_stream_id,
            self.output_stream_id, self.function,
            [(k, _canon(v)) for k, v in self.options], self.seq,
        )


@dataclass(frozen=True)
class TransformRunRecord:
    """One deterministic transform evaluation over booked events (frozen).

    Input event ids and output event ids are sorted by input digest, so
    two runs over the same ledger produce the same record.
    """

    run_id: str
    transform_id: str
    function: str
    input_event_ids: Tuple[str, ...]
    output_event_ids: Tuple[str, ...]
    input_count: int
    output_count: int
    seq: int
    digest: str
    schema: str = STREAM_PROCESSING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "transform-run", self.run_id, self.transform_id, self.function,
            list(self.input_event_ids), list(self.output_event_ids),
            self.input_count, self.output_count, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_STREAM_REGISTERED = "stream.stream-registered"
KIND_EVENT_INGESTED = "stream.event-ingested"
KIND_WINDOW_DEFINED = "stream.window-defined"
KIND_AGGREGATED = "stream.aggregated"
KIND_JOIN_DEFINED = "stream.join-defined"
KIND_JOINED = "stream.joined"
KIND_REJECTED = "stream.rejected"
KIND_SOURCE_BOUND = "stream.source-bound"
KIND_SINK_BOUND = "stream.sink-bound"
KIND_TRANSFORM_BOUND = "stream.transform-bound"
KIND_TRANSFORM_RUN = "stream.transform-run"
_KINDS = (
    KIND_STREAM_REGISTERED, KIND_EVENT_INGESTED, KIND_WINDOW_DEFINED,
    KIND_AGGREGATED, KIND_JOIN_DEFINED, KIND_JOINED, KIND_REJECTED,
    KIND_SOURCE_BOUND, KIND_SINK_BOUND, KIND_TRANSFORM_BOUND,
    KIND_TRANSFORM_RUN,
)

# Keys that may never cross the audit boundary: raw values may carry PII.
_BANNED_KEYS = {"key", "value", "pairs"}


def stream_processing_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the stream-processing module."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise StreamProcessingError("detail must be a mapping")
    if any(k in detail for k in _BANNED_KEYS):
        raise StreamProcessingError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": STREAM_PROCESSING_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class StreamProcessing:
    """Deterministic stream-windowing bookkeeping.

    All state mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume their
    seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._streams: Dict[str, StreamRecord] = {}
        self._events: Dict[str, EventRecord] = {}
        self._events_by_stream: Dict[str, List[str]] = {}
        self._watermarks: Dict[str, int] = {}
        self._event_counter = 0
        self._windows: Dict[str, WindowRecord] = {}
        self._aggregated_windows: set = set()
        self._agg_counter = 0
        self._joins: Dict[str, JoinRecord] = {}
        self._join_counter = 0
        self._results: Dict[str, JoinResult] = {}
        # Source/sink/transform topology (Kafka Streams / Flink shape).
        self._sources: Dict[str, SourceRecord] = {}
        self._sinks: Dict[str, SinkRecord] = {}
        self._transforms: Dict[str, TransformRecord] = {}
        self._run_counter = 0
        self._audit: List[Dict[str, Any]] = []
        self._prev_digest = _GENESIS

    # -- internals --------------------------------------------------------

    def _use_seq(self, seq: int) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last {self._seq})"
            )
        self._seq = seq
        return seq

    def _emit(self, kind: str, detail: Mapping[str, Any], seq: int) -> None:
        self._audit.append(stream_processing_audit_event(kind, detail, seq))

    def _reject_locked(
        self, exc: StreamProcessingError, detail: Mapping[str, Any], seq: int
    ) -> None:
        merged = dict(detail)
        merged["error"] = type(exc).__name__
        self._emit(KIND_REJECTED, merged, seq)
        raise exc

    # -- streams ----------------------------------------------------------

    def register_stream(
        self, stream_id: str, seq: int, key_fields: Sequence[str] = ()
    ) -> StreamRecord:
        """Pin a named stream with optional key field names."""
        with self._lock:
            sid = _check_nonempty_str(stream_id, "stream_id")
            seq = self._use_seq(seq)
            fields: Tuple[str, ...] = ()
            try:
                if not isinstance(key_fields, (list, tuple)):
                    raise BadStreamError("key_fields must be a list/tuple")
                for f in key_fields:
                    if not isinstance(f, str) or not f.strip():
                        raise BadStreamError(
                            "key_fields entries must be non-empty strings"
                        )
                fields = tuple(f.strip() for f in key_fields)
            except StreamProcessingError as exc:
                self._reject_locked(exc, {"stream_id": sid}, seq)
            if sid in self._streams:
                self._reject_locked(
                    DuplicateStreamError(f"stream already registered: {sid!r}"),
                    {"stream_id": sid}, seq,
                )
            rec = StreamRecord(
                stream_id=sid, key_fields=fields, seq=seq,
                digest=_pin("stream", sid, list(fields), seq),
            )
            self._streams[sid] = rec
            self._events_by_stream[sid] = []
            self._watermarks[sid] = -1
            self._emit(
                KIND_STREAM_REGISTERED,
                {"stream_id": sid, "key_fields": list(fields)}, seq,
            )
            return rec

    def stream_record(self, stream_id: str) -> StreamRecord:
        with self._lock:
            try:
                return self._streams[stream_id]
            except KeyError:
                raise UnknownStreamError(
                    f"unknown stream: {stream_id!r}"
                ) from None

    def stream_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._streams))

    def ingest(
        self, stream_id: str, key: Any, value: Any, event_seq: int, seq: int
    ) -> EventRecord:
        """Book one host-reported event on a stream."""
        with self._lock:
            sid = _check_nonempty_str(stream_id, "stream_id")
            seq = self._use_seq(seq)
            if sid not in self._streams:
                self._reject_locked(
                    UnknownStreamError(f"unknown stream: {sid!r}"),
                    {"stream_id": sid}, seq,
                )
            try:
                event_seq = _check_seq(event_seq, "event_seq")
                ckey = _canon(key)
                cval = _canon(value)
            except StreamProcessingError as exc:
                self._reject_locked(exc, {"stream_id": sid}, seq)
            late = event_seq < self._watermarks[sid]
            self._event_counter += 1
            eid = f"evt-{self._event_counter}"
            rec = EventRecord(
                event_id=eid, stream_id=sid, key=ckey, value=cval,
                event_seq=event_seq, late=late, seq=seq,
                digest=_pin(
                    "event", eid, sid, ckey, cval, event_seq, late, seq
                ),
            )
            self._events[eid] = rec
            self._events_by_stream[sid].append(eid)
            if event_seq > self._watermarks[sid]:
                self._watermarks[sid] = event_seq
            self._emit(
                KIND_EVENT_INGESTED,
                {"event_id": eid, "stream_id": sid, "late": late}, seq,
            )
            return rec

    def event_record(self, event_id: str) -> EventRecord:
        with self._lock:
            try:
                return self._events[event_id]
            except KeyError:
                raise StreamProcessingError(
                    f"unknown event: {event_id!r}"
                ) from None

    def events_for(self, stream_id: str) -> Tuple[EventRecord, ...]:
        with self._lock:
            if stream_id not in self._streams:
                raise UnknownStreamError(f"unknown stream: {stream_id!r}")
            return tuple(self._events[e] for e in self._events_by_stream[stream_id])

    # -- windows ----------------------------------------------------------

    def window(
        self, window_id: str, stream_id: str, kind: str, size_seq: int,
        seq: int, slide_seq: Optional[int] = None,
    ) -> WindowRecord:
        """Pin a tumbling/sliding window spec over a stream's logical seqs."""
        with self._lock:
            wid = _check_nonempty_str(window_id, "window_id")
            sid = _check_nonempty_str(stream_id, "stream_id")
            seq = self._use_seq(seq)
            if sid not in self._streams:
                self._reject_locked(
                    UnknownStreamError(f"unknown stream: {sid!r}"),
                    {"window_id": wid}, seq,
                )
            try:
                if kind not in WINDOW_KINDS:
                    raise BadWindowError(
                        f"kind must be one of {WINDOW_KINDS}, got {kind!r}"
                    )
                size = _check_positive_int(size_seq, "size_seq")
                if slide_seq is None:
                    slide = size
                else:
                    slide = _check_positive_int(slide_seq, "slide_seq")
                if kind == KIND_TUMBLING and slide != size:
                    raise BadWindowError(
                        "tumbling windows require slide_seq == size_seq"
                    )
                if kind == KIND_SLIDING and slide >= size:
                    raise BadWindowError(
                        "sliding windows require slide_seq < size_seq"
                    )
            except StreamProcessingError as exc:
                self._reject_locked(exc, {"window_id": wid}, seq)
            if wid in self._windows:
                self._reject_locked(
                    DuplicateWindowError(f"window already pinned: {wid!r}"),
                    {"window_id": wid}, seq,
                )
            rec = WindowRecord(
                window_id=wid, stream_id=sid, kind=kind, size_seq=size,
                slide_seq=slide, seq=seq,
                digest=_pin("window", wid, sid, kind, size, slide, seq),
            )
            self._windows[wid] = rec
            self._emit(
                KIND_WINDOW_DEFINED,
                {"window_id": wid, "stream_id": sid, "kind": kind,
                 "size_seq": size, "slide_seq": slide}, seq,
            )
            return rec

    def window_record(self, window_id: str) -> WindowRecord:
        with self._lock:
            try:
                return self._windows[window_id]
            except KeyError:
                raise UnknownWindowError(
                    f"unknown window: {window_id!r}"
                ) from None

    def window_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._windows))

    # -- aggregation ------------------------------------------------------

    @staticmethod
    def _apply_function(
        function: str, values: List[float]
    ) -> Tuple[Any, int]:
        """Apply a pinned aggregate; returns (value, skipped)."""
        if function == "count":
            return len(values), 0
        nums: List[float] = []
        skipped = 0
        for v in values:
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                skipped += 1
                continue
            nums.append(float(v))
        if function == "sum":
            return sum(nums), skipped
        if function == "min":
            return (min(nums) if nums else None), skipped
        if function == "max":
            return (max(nums) if nums else None), skipped
        if function == "avg":
            return (sum(nums) / len(nums) if nums else None), skipped
        raise BadAggregateError(f"unknown function: {function!r}")  # pragma: no cover

    def aggregate(self, window_id: str, seq: int, function: str = "count") -> AggregateResult:
        """Aggregate closed window instances (window end <= ``seq``)."""
        with self._lock:
            wid = _check_nonempty_str(window_id, "window_id")
            seq = self._use_seq(seq)
            if function not in AGGREGATE_FUNCTIONS:
                self._reject_locked(
                    BadAggregateError(
                        f"function must be one of {AGGREGATE_FUNCTIONS}"
                    ),
                    {"window_id": wid}, seq,
                )
            try:
                rec = self.window_record(wid)
            except StreamProcessingError as exc:
                self._reject_locked(exc, {"window_id": wid}, seq)
            events = [self._events[e] for e in self._events_by_stream[rec.stream_id]]
            # Window instances whose end (start+size) <= seq are closed.
            starts: set = set()
            for ev in events:
                for s in _window_instances(rec.kind, rec.size_seq, rec.slide_seq, ev.event_seq):
                    if s + rec.size_seq <= seq:
                        starts.add(s)
            # Aggregate the latest closed instance (deterministic single choice).
            if not starts:
                start = 0
            else:
                start = max(starts)
            values: List[float] = []
            for ev in events:
                if start <= ev.event_seq < start + rec.size_seq:
                    values.append(ev.value)
            value, skipped = self._apply_function(function, values)
            self._agg_counter += 1
            aid = f"agg-{self._agg_counter}"
            res = AggregateResult(
                agg_id=aid, window_id=wid, function=function,
                window_start=start, window_end=start + rec.size_seq,
                count=len(values), skipped=skipped, value=value, seq=seq,
                digest=_pin(
                    "aggregate", aid, wid, function, start,
                    start + rec.size_seq, len(values), skipped, value, seq
                ),
            )
            self._aggregated_windows.add(wid)
            self._emit(
                KIND_AGGREGATED,
                {"agg_id": aid, "window_id": wid, "function": function,
                 "count": len(values)}, seq,
            )
            return res

    # -- joins ------------------------------------------------------------

    def join(
        self, join_id: str, left_window_id: str, right_window_id: str,
        seq: int, how: str = JOIN_INNER, tolerance_seq: int = 0,
    ) -> JoinRecord:
        """Pin a keyed window join spec."""
        with self._lock:
            jid = _check_nonempty_str(join_id, "join_id")
            lid = _check_nonempty_str(left_window_id, "left_window_id")
            rid = _check_nonempty_str(right_window_id, "right_window_id")
            seq = self._use_seq(seq)
            if lid not in self._windows:
                self._reject_locked(
                    UnknownWindowError(f"unknown window: {lid!r}"),
                    {"join_id": jid}, seq,
                )
            if rid not in self._windows:
                self._reject_locked(
                    UnknownWindowError(f"unknown window: {rid!r}"),
                    {"join_id": jid}, seq,
                )
            try:
                if how not in JOIN_TYPES:
                    raise BadJoinError(
                        f"how must be one of {JOIN_TYPES}, got {how!r}"
                    )
                tol = _check_seq(tolerance_seq, "tolerance_seq")
            except StreamProcessingError as exc:
                self._reject_locked(exc, {"join_id": jid}, seq)
            if jid in self._joins:
                self._reject_locked(
                    DuplicateJoinError(f"join already pinned: {jid!r}"),
                    {"join_id": jid}, seq,
                )
            rec = JoinRecord(
                join_id=jid, left_window_id=lid, right_window_id=rid,
                how=how, tolerance_seq=tol, seq=seq,
                digest=_pin("join", jid, lid, rid, how, tol, seq),
            )
            self._joins[jid] = rec
            self._emit(
                KIND_JOIN_DEFINED,
                {"join_id": jid, "left": lid, "right": rid, "how": how,
                 "tolerance_seq": tol}, seq,
            )
            return rec

    def join_record(self, join_id: str) -> JoinRecord:
        with self._lock:
            try:
                return self._joins[join_id]
            except KeyError:
                raise UnknownJoinError(
                    f"unknown join: {join_id!r}"
                ) from None

    def join_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._joins))

    def evaluate_join(self, join_id: str, seq: int) -> JoinResult:
        """Evaluate a pinned join over the two windows' buffered events."""
        with self._lock:
            jid = _check_nonempty_str(join_id, "join_id")
            seq = self._use_seq(seq)
            try:
                rec = self.join_record(jid)
            except StreamProcessingError as exc:
                self._reject_locked(exc, {"join_id": jid}, seq)
            left = self._windows[rec.left_window_id]
            right = self._windows[rec.right_window_id]
            left_events = [
                self._events[e] for e in self._events_by_stream[left.stream_id]
            ]
            right_events = [
                self._events[e] for e in self._events_by_stream[right.stream_id]
            ]
            # Bucket right events by key for deterministic matching.
            right_by_key: Dict[str, List[EventRecord]] = {}
            for ev in right_events:
                k = jcs_canonical_json(_canon(ev.key)).decode()
                right_by_key.setdefault(k, []).append(ev)
            for lst in right_by_key.values():
                lst.sort(key=lambda e: e.digest)
            left_sorted = sorted(left_events, key=lambda e: e.digest)
            pairs: List[JoinPair] = []
            matched = 0
            unmatched_left = 0
            self._join_counter += 1
            rid = f"jres-{self._join_counter}"
            for lev in left_sorted:
                k = jcs_canonical_json(_canon(lev.key)).decode()
                candidates = right_by_key.get(k, [])
                hit: Optional[EventRecord] = None
                for rev in candidates:
                    if abs(rev.event_seq - lev.event_seq) <= rec.tolerance_seq:
                        hit = rev
                        break
                if hit is not None:
                    matched += 1
                    pairs.append(JoinPair(
                        left_event_id=lev.event_id,
                        right_event_id=hit.event_id, key=lev.key, seq=seq,
                        digest=_pin(
                            "pair", lev.event_id, hit.event_id,
                            _canon(lev.key), seq
                        ),
                    ))
                elif rec.how == JOIN_LEFT:
                    unmatched_left += 1
                    pairs.append(JoinPair(
                        left_event_id=lev.event_id, right_event_id=None,
                        key=lev.key, seq=seq,
                        digest=_pin(
                            "pair", lev.event_id, None, _canon(lev.key), seq
                        ),
                    ))
            res = JoinResult(
                result_id=rid, join_id=jid, pairs=tuple(pairs),
                matched=matched, unmatched_left=unmatched_left, seq=seq,
                digest=_pin(
                    "join-result", rid, jid,
                    [p.digest for p in pairs], matched, unmatched_left, seq
                ),
            )
            self._results[rid] = res
            self._emit(
                KIND_JOINED,
                {"result_id": rid, "join_id": jid, "matched": matched,
                 "unmatched_left": unmatched_left}, seq,
            )
            return res

    # -- topology (source / sink / transform) -------------------------------

    @staticmethod
    def _check_transform_options(
        function: str, options: Any
    ) -> Tuple[Tuple[str, Any], ...]:
        """Validate and canonicalize per-function transform options."""
        if options is None:
            opts: Mapping[str, Any] = {}
        elif isinstance(options, Mapping):
            opts = options
        else:
            raise BadTransformError("options must be a mapping or None")
        if function == TRANSFORM_IDENTITY:
            if opts:
                raise BadTransformError("identity takes no options")
            return ()
        if function == TRANSFORM_FILTER:
            try:
                field = opts["field"]
                if not isinstance(field, str) or not field.strip():
                    raise BadTransformError(
                        "filter options need a non-empty 'field' string"
                    )
                target = _canon(opts["value"])
            except KeyError as exc:
                raise BadTransformError(
                    f"filter options missing {exc}"
                ) from None
            return (("field", field.strip()), ("value", target))
        # function == TRANSFORM_PROJECT
        try:
            fields_raw = opts["fields"]
        except KeyError as exc:
            raise BadTransformError(
                "project options need a 'fields' list"
            ) from None
        if not isinstance(fields_raw, (list, tuple)) or not fields_raw:
            raise BadTransformError("project 'fields' must be a non-empty list")
        fields: List[str] = []
        for f in fields_raw:
            if not isinstance(f, str) or not f.strip():
                raise BadTransformError(
                    "project 'fields' entries must be non-empty strings"
                )
            fields.append(f.strip())
        return (("fields", tuple(sorted(set(fields)))),)

    @staticmethod
    def _apply_transform(
        function: str,
        options: Tuple[Tuple[str, Any], ...],
        key: Any,
        value: Any,
    ) -> Any:
        """Apply a pinned transform function; ``_DROP`` means the event is
        filtered out. Never raises on policy."""
        if function == TRANSFORM_IDENTITY:
            return value
        if function == TRANSFORM_FILTER:
            field = options[0][1]
            target = options[1][1]
            if isinstance(value, Mapping) and value.get(field) == target:
                return value
            return _DROP
        # function == TRANSFORM_PROJECT
        fields = options[0][1]
        if isinstance(value, Mapping):
            return {f: value[f] for f in fields if f in value}
        return _DROP

    def source(self, source_id: str, stream_id: str, seq: int) -> SourceRecord:
        """Pin a source connector that feeds ``stream_id``."""
        with self._lock:
            sid = _check_nonempty_str(source_id, "source_id")
            stid = _check_nonempty_str(stream_id, "stream_id")
            seq = self._use_seq(seq)
            if stid not in self._streams:
                self._reject_locked(
                    UnknownStreamError(f"unknown stream: {stid!r}"),
                    {"source_id": sid}, seq,
                )
            if sid in self._sources:
                self._reject_locked(
                    DuplicateSourceError(f"source already bound: {sid!r}"),
                    {"source_id": sid}, seq,
                )
            rec = SourceRecord(
                source_id=sid, stream_id=stid, seq=seq,
                digest=_pin("source", sid, stid, seq),
            )
            self._sources[sid] = rec
            self._emit(
                KIND_SOURCE_BOUND,
                {"source_id": sid, "stream_id": stid}, seq,
            )
            return rec

    def source_record(self, source_id: str) -> SourceRecord:
        with self._lock:
            try:
                return self._sources[source_id]
            except KeyError:
                raise UnknownSourceError(
                    f"unknown source: {source_id!r}"
                ) from None

    def source_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._sources))

    def sink(self, sink_id: str, stream_id: str, seq: int) -> SinkRecord:
        """Pin a sink connector that drains ``stream_id``."""
        with self._lock:
            sid = _check_nonempty_str(sink_id, "sink_id")
            stid = _check_nonempty_str(stream_id, "stream_id")
            seq = self._use_seq(seq)
            if stid not in self._streams:
                self._reject_locked(
                    UnknownStreamError(f"unknown stream: {stid!r}"),
                    {"sink_id": sid}, seq,
                )
            if sid in self._sinks:
                self._reject_locked(
                    DuplicateSinkError(f"sink already bound: {sid!r}"),
                    {"sink_id": sid}, seq,
                )
            rec = SinkRecord(
                sink_id=sid, stream_id=stid, seq=seq,
                digest=_pin("sink", sid, stid, seq),
            )
            self._sinks[sid] = rec
            self._emit(
                KIND_SINK_BOUND,
                {"sink_id": sid, "stream_id": stid}, seq,
            )
            return rec

    def sink_record(self, sink_id: str) -> SinkRecord:
        with self._lock:
            try:
                return self._sinks[sink_id]
            except KeyError:
                raise UnknownSinkError(
                    f"unknown sink: {sink_id!r}"
                ) from None

    def sink_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._sinks))

    def transform(
        self, transform_id: str, input_stream_id: str, output_stream_id: str,
        seq: int, function: str = TRANSFORM_IDENTITY,
        options: Optional[Mapping[str, Any]] = None,
    ) -> TransformRecord:
        """Pin a topology edge: read ``input_stream_id``, apply the pinned
        ``function``, write ``output_stream_id`` on ``run_transform``."""
        with self._lock:
            tid = _check_nonempty_str(transform_id, "transform_id")
            iid = _check_nonempty_str(input_stream_id, "input_stream_id")
            oid = _check_nonempty_str(output_stream_id, "output_stream_id")
            seq = self._use_seq(seq)
            if iid not in self._streams:
                self._reject_locked(
                    UnknownStreamError(f"unknown stream: {iid!r}"),
                    {"transform_id": tid}, seq,
                )
            if oid not in self._streams:
                self._reject_locked(
                    UnknownStreamError(f"unknown stream: {oid!r}"),
                    {"transform_id": tid}, seq,
                )
            try:
                if function not in TRANSFORM_FUNCTIONS:
                    raise BadTransformError(
                        f"function must be one of {TRANSFORM_FUNCTIONS}, "
                        f"got {function!r}"
                    )
                canon_opts = self._check_transform_options(function, options)
            except StreamProcessingError as exc:
                self._reject_locked(exc, {"transform_id": tid}, seq)
            if iid == oid:
                self._reject_locked(
                    BadTransformError("input and output streams must differ"),
                    {"transform_id": tid}, seq,
                )
            if tid in self._transforms:
                self._reject_locked(
                    DuplicateTransformError(f"transform already pinned: {tid!r}"),
                    {"transform_id": tid}, seq,
                )
            rec = TransformRecord(
                transform_id=tid, input_stream_id=iid,
                output_stream_id=oid, function=function,
                options=canon_opts, seq=seq,
                digest=_pin(
                    "transform", tid, iid, oid, function,
                    [(k, _canon(v)) for k, v in canon_opts], seq,
                ),
            )
            self._transforms[tid] = rec
            audit_detail: Dict[str, Any] = {
                "transform_id": tid, "input_stream_id": iid,
                "output_stream_id": oid, "function": function,
            }
            if canon_opts:
                # Field names only: target values never cross the audit
                # boundary.
                audit_detail["option_keys"] = [k for k, _ in canon_opts]
            self._emit(KIND_TRANSFORM_BOUND, audit_detail, seq)
            return rec

    def transform_record(self, transform_id: str) -> TransformRecord:
        with self._lock:
            try:
                return self._transforms[transform_id]
            except KeyError:
                raise UnknownTransformError(
                    f"unknown transform: {transform_id!r}"
                ) from None

    def transform_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._transforms))

    def _book_transform_event(
        self, stream_id: str, key: Any, value: Any, event_seq: int, seq: int
    ) -> EventRecord:
        """Book one transform-output event under an already-bumped seq."""
        late = event_seq < self._watermarks[stream_id]
        self._event_counter += 1
        eid = f"evt-{self._event_counter}"
        rec = EventRecord(
            event_id=eid, stream_id=stream_id, key=key, value=value,
            event_seq=event_seq, late=late, seq=seq,
            digest=_pin("event", eid, stream_id, key, value, event_seq, late, seq),
        )
        self._events[eid] = rec
        self._events_by_stream[stream_id].append(eid)
        if event_seq > self._watermarks[stream_id]:
            self._watermarks[stream_id] = event_seq
        self._emit(
            KIND_EVENT_INGESTED,
            {"event_id": eid, "stream_id": stream_id, "late": late}, seq,
        )
        return rec

    def run_transform(self, transform_id: str, seq: int) -> TransformRunRecord:
        """Evaluate a pinned transform over the input stream's booked events.

        Matching the house discipline of ``evaluate_join``: deterministic,
        host-reported events in, frozen run record out; output events are
        booked on the output stream so transforms chain into topologies."""
        with self._lock:
            tid = _check_nonempty_str(transform_id, "transform_id")
            seq = self._use_seq(seq)
            try:
                rec = self.transform_record(tid)
            except StreamProcessingError as exc:
                self._reject_locked(exc, {"transform_id": tid}, seq)
            inputs = sorted(
                (self._events[e]
                 for e in self._events_by_stream[rec.input_stream_id]),
                key=lambda e: e.digest,
            )
            out_events: List[EventRecord] = []
            for ev in inputs:
                result = self._apply_transform(
                    rec.function, rec.options, ev.key, ev.value
                )
                if result is _DROP:
                    continue
                out_events.append(
                    self._book_transform_event(
                        rec.output_stream_id, ev.key, result, ev.event_seq, seq
                    )
                )
            self._run_counter += 1
            rid = f"run-{self._run_counter}"
            res = TransformRunRecord(
                run_id=rid, transform_id=tid, function=rec.function,
                input_event_ids=tuple(e.event_id for e in inputs),
                output_event_ids=tuple(e.event_id for e in out_events),
                input_count=len(inputs), output_count=len(out_events), seq=seq,
                digest=_pin(
                    "transform-run", rid, tid, rec.function,
                    [e.event_id for e in inputs],
                    [e.event_id for e in out_events],
                    len(inputs), len(out_events), seq,
                ),
            )
            self._emit(
                KIND_TRANSFORM_RUN,
                {"run_id": rid, "transform_id": tid,
                 "input_count": len(inputs),
                 "output_count": len(out_events)}, seq,
            )
            return res

    # -- views ------------------------------------------------------------

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read view: stream/window/join counts (seq validated, not consumed)."""
        _check_seq(seq, "seq")
        with self._lock:
            return {
                "streams": len(self._streams),
                "events": len(self._events),
                "windows": len(self._windows),
                "joins": len(self._joins),
                "seq": seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    def as_dict(self, seq: int) -> Dict[str, Any]:
        """Pure read view of the whole ledger (ids and pins only)."""
        _check_seq(seq, "seq")
        with self._lock:
            return {
                "version": STREAM_PROCESSING_VERSION,
                "schema": STREAM_PROCESSING_SCHEMA,
                "streams": {s: r.digest for s, r in self._streams.items()},
                "windows": {w: r.digest for w, r in self._windows.items()},
                "joins": {j: r.digest for j, r in self._joins.items()},
                "seq": seq,
            }


def main() -> None:
    sp = StreamProcessing()
    sp.register_stream("orders", 1, key_fields=["customer"])
    sp.ingest("orders", {"customer": "a"}, 10, 5, 2)
    sp.ingest("orders", {"customer": "a"}, 20, 8, 3)
    sp.window("w1", "orders", KIND_TUMBLING, 10, 4)
    res = sp.aggregate("w1", 20, "sum")
    assert res.value == 30 and res.count == 2
    sp.register_stream("payments", 30, key_fields=["customer"])
    sp.ingest("payments", {"customer": "a"}, 7, 6, 31)
    sp.window("w2", "payments", KIND_TUMBLING, 10, 32)
    sp.join("j1", "w1", "w2", 33, tolerance_seq=3)
    jr = sp.evaluate_join("j1", 34)
    assert jr.matched == 2
    # Topology: source -> transform -> sink.
    sp.source("src-1", "orders", 40)
    sp.register_stream("enriched", 41)
    sp.sink("snk-1", "enriched", 42)
    sp.ingest("orders", {"customer": "b"}, {"amount": 10}, 12, 43)
    sp.ingest("orders", {"customer": "c"}, {"amount": 99}, 13, 44)
    tr = sp.transform(
        "t1", "orders", "enriched", 45, function="filter",
        options={"field": "amount", "value": 10},
    )
    assert tr.verify() and tr.options[0][1] == "amount"
    run = sp.run_transform("t1", 46)
    assert run.verify() and run.input_count == 4 and run.output_count == 1
    outs = sp.events_for("enriched")
    assert len(outs) == 1 and outs[0].value == {"amount": 10}
    kinds = [e["kind"] for e in sp.audit_log()]
    assert KIND_SOURCE_BOUND in kinds and KIND_TRANSFORM_RUN in kinds
    print("stream-processing OK: stream, window, aggregate, join, pins, "
          "source, sink, transform")


if __name__ == "__main__":
    main()
