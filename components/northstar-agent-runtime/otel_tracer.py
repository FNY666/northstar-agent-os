"""OpenTelemetry-style distributed tracing bookkeeping.

Research note: OpenTelemetry's trace model (W3C trace-context, ``traceparent``
propagation, span events and status codes) is the industry standard for
distributed tracing (CNCF, trace spec). A trace is a tree of spans linked by
``trace_id``; cross-process linkage travels in the ``traceparent`` header so a
downstream service can continue the same trace. This module implements that
shape as a deterministic, single-host bookkeeping ledger: it records span
lifecycles, parent/child links, events, and propagation headers. It owns no
network and no clock — the host supplies caller int ``seq`` values for ordering
and duration, and injects/extracts real headers at its process boundary.

* **Spans** — ``start_span(name, seq, ...)`` mints a frozen ``Span`` with a
  fresh ``trace_id`` (32 hex chars) unless joined to a parent (then the parent's
  trace id is inherited) and a fresh ``span_id`` (16 hex chars). Ending a span
  freezes a ``SpanRecord`` with ``duration_seqs = end_seq - start_seq``.
* **Kinds** — ``INTERNAL`` / ``SERVER`` / ``CLIENT`` / ``PRODUCER`` /
  ``CONSUMER`` (the OTel span-kind set). A ``SERVER`` span should be the root
  of an inbound trace; ``CLIENT`` spans initiate outbound calls.
* **Status** — ``UNSET`` / ``OK`` / ``ERROR``; ending with ``ERROR`` may carry
  a description.
* **Propagation** — ``propagate(span_id, seq)`` emits a frozen
  ``TraceContext`` carrying the W3C ``traceparent`` value
  ``00-<trace-id>-<span-id>-01``; ``inject(headers, span_id, seq)`` returns a
  copy of the headers dict with ``traceparent`` set; ``extract(headers, seq)``
  parses it back fail-closed.
* **Events** — ``add_event`` records timestamped (caller seq) span events;
  ``set_attributes`` merges attributes into an in-flight span.
* **Fail-closed** — unknown span ids, double ``end_span``, ending with an
  ``end_seq`` earlier than the start seq, unknown span kinds or status codes,
  malformed ``traceparent`` values, and empty span names all raise, never
  silently no-op.
* **No wall-clock** — ``seq`` values are caller-supplied ints (the same
  ordering discipline as the sibling batch modules); ids come from an
  injectable ``id_factory`` (default: ``secrets.SystemRandom``) so tests are
  deterministic while production gets cryptographic ids.

Honest scope: this is *tracing bookkeeping*, not an OTel SDK — there is no
exporter, no sampler, no real clock, and the "durations" are seq deltas, not
time. A ``SpanRecord`` proves "this span was opened and closed in this order
with these attributes", never "this is how long it took" or "the downstream
service saw the same trace". Pair with the durable audit writer for crash
recovery, and with ``otel_metrics``/``otel_logs`` (not in this module) for the
full signal set.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

#: Module version.
OTEL_TRACER_VERSION = "otel-tracer.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.otel-tracer.v1"

#: W3C trace-context version field.
_TRACEPARENT_VERSION = "00"

#: Default sampling flag in the emitted traceparent ("01" = sampled).
_TRACEPARENT_SAMPLED = "01"

#: W3C span-id length (16 hex chars = 64 bits) and trace-id length (32 hex
#: chars = 128 bits).
_SPAN_ID_HEX_LEN = 16
_TRACE_ID_HEX_LEN = 32

#: OTel span kinds.
SPAN_KIND_INTERNAL = "internal"
SPAN_KIND_SERVER = "server"
SPAN_KIND_CLIENT = "client"
SPAN_KIND_PRODUCER = "producer"
SPAN_KIND_CONSUMER = "consumer"
SPAN_KINDS = frozenset(
    {
        SPAN_KIND_INTERNAL,
        SPAN_KIND_SERVER,
        SPAN_KIND_CLIENT,
        SPAN_KIND_PRODUCER,
        SPAN_KIND_CONSUMER,
    }
)

#: OTel span status codes.
STATUS_UNSET = "unset"
STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_CODES = frozenset({STATUS_UNSET, STATUS_OK, STATUS_ERROR})


class TracerError(Exception):
    """Base error for the tracer."""


class UnknownSpanError(TracerError):
    """Raised when an operation names a span id the tracer does not know."""


class SpanClosedError(TracerError):
    """Raised when an operation targets an already-ended span."""


class InvalidTraceparentError(TracerError):
    """Raised when a traceparent header value does not parse."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TracerError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise TracerError(f"{name} must be non-negative")
    return value


def _check_name(value: Any, what: str = "span name") -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value:
        raise TracerError(f"{what} must be a non-empty str")
    return value


def _check_kind(value: Any) -> str:
    if not isinstance(value, str) or value not in SPAN_KINDS:
        raise TracerError(
            f"span kind must be one of {sorted(SPAN_KINDS)}, got {value!r}"
        )
    return value


def _check_status(value: Any) -> str:
    if not isinstance(value, str) or value not in STATUS_CODES:
        raise TracerError(
            f"status must be one of {sorted(STATUS_CODES)}, got {value!r}"
        )
    return value


def _check_id_hex(value: Any, length: int, what: str) -> str:
    if not isinstance(value, str):
        raise TracerError(f"{what} must be a str, got {type(value).__name__}")
    if len(value) != length:
        raise TracerError(f"{what} must be {length} hex chars, got {value!r}")
    try:
        int(value, 16)
    except ValueError:
        raise TracerError(f"{what} must be hex, got {value!r}")
    if value == "0" * length:
        raise TracerError(f"{what} must not be all zeros")
    return value


def _default_id_factory() -> Callable[[int], str]:
    rng = secrets.SystemRandom()

    def make(num_bytes: int) -> str:
        if num_bytes not in (8, 16):
            raise TracerError("id length must be 8 or 16 bytes")
        return rng.getrandbits(num_bytes * 8).to_bytes(num_bytes, "big").hex()

    return make


def _digest_pin(*parts: Any) -> str:
    """Deterministic ``sha256:`` pin over canonicalized parts."""
    body = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _check_attributes(value: Any, what: str = "attributes") -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TracerError(f"{what} must be a mapping, got {type(value).__name__}")
    out: dict[str, Any] = {}
    for key, val in value.items():
        if not isinstance(key, str) or not key:
            raise TracerError(f"{what} keys must be non-empty str")
        if isinstance(val, bool) or not isinstance(val, (str, int, float)):
            raise TracerError(
                f"{what}[{key!r}] must be str/int/float (no bool), "
                f"got {type(val).__name__}"
            )
        if isinstance(val, float) and (
            val != val or val in (float("inf"), float("-inf"))
        ):
            raise TracerError(f"{what}[{key!r}] must be a finite float")
        out[key] = val
    return dict(sorted(out.items()))


@dataclass(frozen=True)
class SpanEvent:
    """A timestamped (caller-seq) event recorded on a span."""

    name: str
    seq: int
    attributes: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "seq": self.seq,
            "attributes": self.attributes,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class Span:
    """An in-flight (started, not yet ended) span."""

    span_id: str
    trace_id: str
    name: str
    kind: str
    start_seq: int
    parent_span_id: Optional[str]
    service: str
    attributes: dict[str, Any] = field(default_factory=dict)
    events: tuple[SpanEvent, ...] = ()
    digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": OTEL_TRACER_VERSION,
            "schema": SCHEMA_PIN,
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "name": self.name,
            "kind": self.kind,
            "start_seq": self.start_seq,
            "parent_span_id": self.parent_span_id,
            "service": self.service,
            "attributes": self.attributes,
            "events": [e.as_dict() for e in self.events],
            "digest": self.digest,
        }


@dataclass(frozen=True)
class SpanRecord:
    """A completed span: started and ended, frozen."""

    span_id: str
    trace_id: str
    name: str
    kind: str
    start_seq: int
    end_seq: int
    duration_seqs: int
    parent_span_id: Optional[str]
    service: str
    status: str
    status_description: str
    attributes: dict[str, Any] = field(default_factory=dict)
    events: tuple[SpanEvent, ...] = ()
    digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": OTEL_TRACER_VERSION,
            "schema": SCHEMA_PIN,
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "name": self.name,
            "kind": self.kind,
            "start_seq": self.start_seq,
            "end_seq": self.end_seq,
            "duration_seqs": self.duration_seqs,
            "parent_span_id": self.parent_span_id,
            "service": self.service,
            "status": self.status,
            "status_description": self.status_description,
            "attributes": self.attributes,
            "events": [e.as_dict() for e in self.events],
            "digest": self.digest,
        }


@dataclass(frozen=True)
class TraceContext:
    """A parsed/propagated W3C trace context (traceparent value)."""

    trace_id: str
    span_id: str
    sampled: bool
    traceparent: str
    digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": OTEL_TRACER_VERSION,
            "schema": SCHEMA_PIN,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "sampled": self.sampled,
            "traceparent": self.traceparent,
            "digest": self.digest,
        }


class OTELTracer:
    """Deterministic single-host OpenTelemetry-style span ledger.

    Spans are in-flight :class:`Span` records until :meth:`end_span` freezes
    them into :class:`SpanRecord`; propagation headers follow the W3C
    ``traceparent`` shape. Ordering and durations are expressed in
    caller-supplied int ``seq`` values — the module never touches a clock.
    """

    def __init__(
        self,
        service_name: str,
        id_factory: Optional[Callable[[int], str]] = None,
    ) -> None:
        self._service = _check_name(service_name, "service name")
        if id_factory is not None and not callable(id_factory):
            raise TracerError("id_factory must be callable")
        self._id_factory = id_factory or _default_id_factory()
        self._lock = threading.RLock()
        self._spans: dict[str, Span] = {}
        self._ended: set[str] = set()
        self._completed: list[SpanRecord] = []
        self._seq_counter = 0

    @property
    def service(self) -> str:
        return self._service

    def _new_trace_id(self) -> str:
        return _check_id_hex(
            self._id_factory(16), _TRACE_ID_HEX_LEN, "trace id"
        )

    def _new_span_id(self) -> str:
        return _check_id_hex(self._id_factory(8), _SPAN_ID_HEX_LEN, "span id")

    def start_span(
        self,
        name: str,
        seq: Any,
        parent: Optional[Any] = None,
        kind: str = SPAN_KIND_INTERNAL,
        attributes: Optional[dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> Span:
        """Open a new span and register it as in-flight."""
        name = _check_name(name)
        seq = _check_seq(seq)
        kind = _check_kind(kind)
        attributes = _check_attributes(attributes)
        with self._lock:
            if parent is not None:
                if not isinstance(parent, Span):
                    raise TracerError("parent must be a Span or None")
                if parent.span_id in self._ended or parent.span_id not in self._spans:
                    raise SpanClosedError("parent span is not in-flight")
                parent_span_id: Optional[str] = parent.span_id
                use_trace_id = parent.trace_id
            else:
                parent_span_id = None
                use_trace_id = (
                    _check_id_hex(trace_id, _TRACE_ID_HEX_LEN, "trace id")
                    if trace_id is not None
                    else self._new_trace_id()
                )
            span_id = self._new_span_id()
            digest = _digest_pin(
                "span", use_trace_id, span_id, name, kind, seq, parent_span_id,
                self._service, attributes,
            )
            span = Span(
                span_id=span_id,
                trace_id=use_trace_id,
                name=name,
                kind=kind,
                start_seq=seq,
                parent_span_id=parent_span_id,
                service=self._service,
                attributes=attributes,
                digest=digest,
            )
            self._spans[span_id] = span
            self._seq_counter = max(self._seq_counter, seq)
            return span

    def _live_span(self, span_id: Any) -> Span:
        _check_id_hex(span_id, _SPAN_ID_HEX_LEN, "span id")
        span = self._spans.get(span_id)
        if span is None:
            raise UnknownSpanError(f"unknown span id {span_id!r}")
        if span.span_id in self._ended:
            raise SpanClosedError(f"span {span_id!r} already ended")
        return span

    def set_attributes(
        self, span_id: Any, attributes: dict[str, Any], seq: Any
    ) -> Span:
        """Merge attributes into an in-flight span (returns the updated view)."""
        seq = _check_seq(seq)
        attributes = _check_attributes(attributes)
        with self._lock:
            span = self._live_span(span_id)
            merged = dict(span.attributes)
            merged.update(attributes)
            updated = Span(
                span_id=span.span_id,
                trace_id=span.trace_id,
                name=span.name,
                kind=span.kind,
                start_seq=span.start_seq,
                parent_span_id=span.parent_span_id,
                service=span.service,
                attributes=dict(sorted(merged.items())),
                events=span.events,
                digest=_digest_pin(
                    "span", span.trace_id, span.span_id, span.name,
                    span.kind, span.start_seq, span.parent_span_id,
                    span.service, dict(sorted(merged.items())),
                ),
            )
            self._spans[span_id] = updated
            self._seq_counter = max(self._seq_counter, seq)
            return updated

    def add_event(
        self,
        span_id: Any,
        event_name: str,
        seq: Any,
        attributes: Optional[dict[str, Any]] = None,
    ) -> Span:
        """Record a named event on an in-flight span."""
        seq = _check_seq(seq)
        event_name = _check_name(event_name, "event name")
        attributes = _check_attributes(attributes)
        with self._lock:
            span = self._live_span(span_id)
            event = SpanEvent(name=event_name, seq=seq, attributes=attributes)
            updated = Span(
                span_id=span.span_id,
                trace_id=span.trace_id,
                name=span.name,
                kind=span.kind,
                start_seq=span.start_seq,
                parent_span_id=span.parent_span_id,
                service=span.service,
                attributes=span.attributes,
                events=span.events + (event,),
                digest=span.digest,
            )
            self._spans[span_id] = updated
            self._seq_counter = max(self._seq_counter, seq)
            return updated

    def end_span(
        self,
        span_id: Any,
        seq: Any,
        status: str = STATUS_UNSET,
        status_description: str = "",
    ) -> SpanRecord:
        """Freeze an in-flight span into a completed SpanRecord."""
        seq = _check_seq(seq)
        status = _check_status(status)
        if not isinstance(status_description, str):
            raise TracerError("status_description must be a str")
        with self._lock:
            span = self._live_span(span_id)
            if seq < span.start_seq:
                raise TracerError(
                    "end seq must not precede the span's start seq"
                )
            record = SpanRecord(
                span_id=span.span_id,
                trace_id=span.trace_id,
                name=span.name,
                kind=span.kind,
                start_seq=span.start_seq,
                end_seq=seq,
                duration_seqs=seq - span.start_seq,
                parent_span_id=span.parent_span_id,
                service=span.service,
                status=status,
                status_description=status_description,
                attributes=span.attributes,
                events=span.events,
                digest=_digest_pin(
                    "span-record", span.trace_id, span.span_id, span.name,
                    span.kind, span.start_seq, seq, span.parent_span_id,
                    span.service, status, status_description, span.attributes,
                    [(e.name, e.seq, e.attributes) for e in span.events],
                ),
            )
            self._ended.add(span_id)
            self._completed.append(record)
            self._seq_counter = max(self._seq_counter, seq)
            return record

    def span(self, span_id: Any) -> Span:
        """View an in-flight span (fail-closed on unknown/ended)."""
        with self._lock:
            return self._live_span(span_id)

    def in_flight(self) -> tuple[str, ...]:
        """Span ids of currently open spans, sorted."""
        with self._lock:
            return tuple(
                sorted(sid for sid in self._spans if sid not in self._ended)
            )

    def completed(self) -> tuple[SpanRecord, ...]:
        """Completed spans in completion order."""
        with self._lock:
            return tuple(self._completed)

    def trace(self, trace_id: str) -> tuple[SpanRecord, ...]:
        """Completed spans of one trace, sorted by start seq."""
        _check_id_hex(trace_id, _TRACE_ID_HEX_LEN, "trace id")
        with self._lock:
            records = [r for r in self._completed if r.trace_id == trace_id]
        return tuple(sorted(records, key=lambda r: (r.start_seq, r.span_id)))

    def propagate(self, span_id: Any, seq: Any) -> TraceContext:
        """Emit the W3C traceparent context for an in-flight span."""
        seq = _check_seq(seq)
        with self._lock:
            span = self._live_span(span_id)
            traceparent = (
                f"{_TRACEPARENT_VERSION}-{span.trace_id}-{span.span_id}"
                f"-{_TRACEPARENT_SAMPLED}"
            )
            self._seq_counter = max(self._seq_counter, seq)
            return TraceContext(
                trace_id=span.trace_id,
                span_id=span.span_id,
                sampled=True,
                traceparent=traceparent,
                digest=_digest_pin("trace-context", traceparent),
            )

    def inject(self, headers: dict[str, str], span_id: Any, seq: Any) -> dict[str, str]:
        """Return a copy of ``headers`` with the ``traceparent`` set."""
        if not isinstance(headers, dict):
            raise TracerError("headers must be a dict")
        for key, val in headers.items():
            if not isinstance(key, str) or not isinstance(val, str):
                raise TracerError("headers must be a str->str mapping")
        ctx = self.propagate(span_id, seq)
        out = dict(headers)
        out["traceparent"] = ctx.traceparent
        return out

    def extract(self, headers: dict[str, str], seq: Any) -> TraceContext:
        """Parse a ``traceparent`` header back into a TraceContext."""
        seq = _check_seq(seq)
        if not isinstance(headers, dict):
            raise TracerError("headers must be a dict")
        raw = headers.get("traceparent")
        if not isinstance(raw, str):
            raise InvalidTraceparentError("missing traceparent header")
        parts = raw.split("-")
        if len(parts) != 4:
            raise InvalidTraceparentError(
                f"traceparent must have 4 dash-separated parts, got {raw!r}"
            )
        version, trace_id, span_id, flags = parts
        if version != _TRACEPARENT_VERSION:
            raise InvalidTraceparentError(
                f"unsupported traceparent version {version!r}"
            )
        try:
            _check_id_hex(trace_id, _TRACE_ID_HEX_LEN, "trace id")
            _check_id_hex(span_id, _SPAN_ID_HEX_LEN, "span id")
        except TracerError as exc:
            raise InvalidTraceparentError(
                f"malformed traceparent ids: {exc}"
            ) from exc
        if len(flags) != 2:
            raise InvalidTraceparentError(
                f"traceparent flags must be 2 hex chars, got {flags!r}"
            )
        try:
            flag_int = int(flags, 16)
        except ValueError:
            raise InvalidTraceparentError(
                f"traceparent flags must be hex, got {flags!r}"
            )
        with self._lock:
            self._seq_counter = max(self._seq_counter, seq)
        return TraceContext(
            trace_id=trace_id,
            span_id=span_id,
            sampled=bool(flag_int & 1),
            traceparent=raw,
            digest=_digest_pin("trace-context", raw),
        )

    def start_span_from_context(
        self,
        context: TraceContext,
        name: str,
        seq: Any,
        kind: str = SPAN_KIND_SERVER,
        attributes: Optional[dict[str, Any]] = None,
    ) -> Span:
        """Continue a remote trace: new root span sharing the remote trace id."""
        if not isinstance(context, TraceContext):
            raise TracerError("context must be a TraceContext")
        name = _check_name(name)
        seq = _check_seq(seq)
        kind = _check_kind(kind)
        attributes = _check_attributes(attributes)
        with self._lock:
            span_id = self._new_span_id()
            digest = _digest_pin(
                "span", context.trace_id, span_id, name, kind, seq, None,
                self._service, attributes,
            )
            span = Span(
                span_id=span_id,
                trace_id=context.trace_id,
                name=name,
                kind=kind,
                start_seq=seq,
                parent_span_id=None,
                service=self._service,
                attributes=attributes,
                digest=digest,
            )
            self._spans[span_id] = span
            self._seq_counter = max(self._seq_counter, seq)
            return span


_OTEL_EVENT_KINDS = frozenset(
    {
        "span-started",
        "span-ended",
        "span-attributes-set",
        "span-event-added",
        "context-propagated",
        "context-extracted",
        "context-continued",
        "rejected",
    }
)


def otel_tracer_audit_event(kind: str, seq: Any, **detail: Any) -> dict[str, Any]:
    """Shape a tracer observation as an ``audit.ndjson/1``-style record."""
    if not isinstance(kind, str) or kind not in _OTEL_EVENT_KINDS:
        raise TracerError(
            f"audit kind must be one of {sorted(_OTEL_EVENT_KINDS)}, got {kind!r}"
        )
    seq = _check_seq(seq, "seq")
    record: dict[str, Any] = {
        "version": OTEL_TRACER_VERSION,
        "schema": SCHEMA_PIN,
        "event": kind,
        "audit_seq": seq,
    }
    for key, value in detail.items():
        if not isinstance(key, str) or not key:
            raise TracerError("audit detail keys must be non-empty str")
        record[key] = value
    return record


def main() -> None:
    """Self-check: lifecycle, propagation, extraction, refusals."""
    counter = {"n": 0}

    def factory(num_bytes: int) -> str:
        counter["n"] += 1
        return f"{counter['n']:0{num_bytes * 2}x}"

    tracer = OTELTracer("svc-a", id_factory=factory)
    root = tracer.start_span("root", seq=1, kind="server")
    assert len(root.trace_id) == 32
    assert len(root.span_id) == 16
    child = tracer.start_span("child", seq=2, parent=root, kind="client")
    assert child.trace_id == root.trace_id
    assert child.parent_span_id == root.span_id
    tracer.set_attributes(child.span_id, {"http.route": "/a"}, seq=3)
    tracer.add_event(child.span_id, "retry", seq=4)
    ctx = tracer.propagate(child.span_id, seq=5)
    assert ctx.traceparent.startswith("00-")
    headers = tracer.inject({"x-req": "1"}, child.span_id, seq=6)
    assert headers["traceparent"] == ctx.traceparent
    other = OTELTracer("svc-b", id_factory=factory)
    extracted = other.extract(headers, seq=7)
    assert extracted.trace_id == child.trace_id
    cont = other.start_span_from_context(extracted, "handler", seq=8)
    assert cont.trace_id == child.trace_id
    rec = tracer.end_span(child.span_id, seq=9, status="ok")
    assert rec.duration_seqs == 7
    assert len(rec.events) == 1
    tracer.end_span(root.span_id, seq=10, status="error", status_description="boom")
    completed = tracer.completed()
    assert len(completed) == 2
    trace = tracer.trace(root.trace_id)
    assert [r.span_id for r in trace] == [root.span_id, child.span_id]
    assert tracer.in_flight() == ()
    # Refusals.
    try:
        tracer.end_span(child.span_id, seq=11)
    except SpanClosedError:
        pass
    else:
        raise AssertionError("double end must fail")
    try:
        other.extract({"traceparent": "00-abc-01"}, seq=12)
    except InvalidTraceparentError:
        pass
    else:
        raise AssertionError("malformed traceparent must fail")
    ev = otel_tracer_audit_event("span-started", 13, span_id=root.span_id)
    assert ev["schema"] == SCHEMA_PIN
    print("otel-tracer OK: lifecycle, propagation, extract, continue, refusals")
