"""Distributed tracing: Jaeger/Zipkin-shaped span and trace bookkeeping.

A ``DistributedTracing`` ledger books host-reported tracing decisions as
a deterministic single-host state machine:

- ``span(span_id, trace_id, name, seq, parent_span_id=None, kind=..., tags=...)``
  opens a span: a frozen ``SpanRecord`` pinned by a ``sha256:`` digest.
  Timing is logical (``start_seq``), never wall-clock. Root spans have no
  parent; child spans must reference an existing span (orphan links are
  refused fail-closed).
- ``finish_span(span_id, seq, status=...)`` closes a span into a frozen
  ``FinishedSpan``; ``duration = end_seq - start_seq`` is data, always >= 1
  because mutations consume strictly increasing seqs. Double-finish is
  refused (terminal).
- ``trace(trace_id, seq)`` returns a frozen ``TraceReport`` — a pure read
  view (validates the seq shape, consumes nothing, writes no audit row).
- ``export(trace_id, seq, format=...)`` renders the finished spans of one
  trace as a Jaeger or Zipkin document — pure read view, digest-pinned.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``distributed-tracing.v1``, schema pin ``northstar.distributed-tracing.v1``,
``main()`` self-check.

Honest scope: this module books *host-reported* span claims — it cannot
prove a span was ever executed, cannot measure real time (durations are
logical-seq units, not microseconds), and cannot detect spans the host
never reports. Exported documents are simulated renderings of the ledger,
not wire payloads; pair with a real collector for production.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
DISTRIBUTED_TRACING_VERSION = "distributed-tracing.v1"

#: Schema pin carried by records and audit events.
DISTRIBUTED_TRACING_SCHEMA = "northstar.distributed-tracing.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: OpenTelemetry-style span kinds.
SPAN_KINDS = ("internal", "server", "client", "producer", "consumer")

#: Span status vocabulary.
SPAN_STATUSES = ("unset", "ok", "error")

#: Export format vocabulary.
EXPORT_FORMATS = ("jaeger", "zipkin")


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class DistributedTracingError(ValueError):
    """Base for all distributed-tracing errors."""


class BadSpanError(DistributedTracingError):
    """A span definition was malformed (bad id, name, kind, tags, parent)."""


class DuplicateSpanError(DistributedTracingError):
    """The span id is already booked."""


class UnknownSpanError(DistributedTracingError):
    """No such span id (also used for a missing parent span)."""


class FinishedSpanError(DistributedTracingError):
    """The span is already finished (terminal)."""


class BadTraceError(DistributedTracingError):
    """A trace id was malformed."""


class UnknownTraceError(DistributedTracingError):
    """No spans have been booked under this trace id."""


class BadFormatError(DistributedTracingError):
    """The export format is not in the pinned vocabulary."""


class SeqOrderError(DistributedTracingError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadSpanError(f"{name} must be a non-empty string")
    return value.strip()


def _check_tags(tags: Any) -> Tuple[Tuple[str, Any], ...]:
    if tags is None:
        return ()
    if not isinstance(tags, Mapping):
        raise BadSpanError("tags must be a mapping")
    items: List[Tuple[str, Any]] = []
    for k, v in tags.items():
        if not isinstance(k, str) or not k.strip():
            raise BadSpanError("tag keys must be non-empty strings")
        if isinstance(v, bool) or not isinstance(v, (str, int, float)):
            raise BadSpanError("tag values must be str/int/float")
        if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
            raise BadSpanError("tag values must be finite")
        items.append((k.strip(), v))
    return tuple(sorted(items, key=lambda kv: kv[0]))


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([DISTRIBUTED_TRACING_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SpanRecord:
    """One opened span (frozen). Timing is logical: ``start_seq``."""

    span_id: str
    trace_id: str
    name: str
    kind: str
    parent_span_id: Optional[str]
    tags: Tuple[Tuple[str, Any], ...]
    start_seq: int
    digest: str
    schema: str = DISTRIBUTED_TRACING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "span",
            self.span_id,
            self.trace_id,
            self.name,
            self.kind,
            self.parent_span_id or "",
            list(self.tags),
            self.start_seq,
        )


@dataclass(frozen=True)
class FinishedSpan:
    """One finished span (frozen). ``duration`` is logical-seq units."""

    span_id: str
    trace_id: str
    name: str
    kind: str
    parent_span_id: Optional[str]
    tags: Tuple[Tuple[str, Any], ...]
    start_seq: int
    end_seq: int
    duration: int
    status: str
    digest: str
    schema: str = DISTRIBUTED_TRACING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "finished",
            self.span_id,
            self.trace_id,
            self.name,
            self.kind,
            self.parent_span_id or "",
            list(self.tags),
            self.start_seq,
            self.end_seq,
            self.duration,
            self.status,
        )


@dataclass(frozen=True)
class TraceReport:
    """One trace view (frozen). Pure read: seq validated, not consumed."""

    trace_id: str
    span_ids: Tuple[str, ...]
    open_spans: int
    finished_spans: int
    digest: str
    schema: str = DISTRIBUTED_TRACING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "trace", self.trace_id, list(self.span_ids),
            self.open_spans, self.finished_spans,
        )


@dataclass(frozen=True)
class ExportRecord:
    """One rendered trace document (frozen). Simulated collector output."""

    trace_id: str
    format: str
    document: Mapping[str, Any]
    span_count: int
    digest: str
    schema: str = DISTRIBUTED_TRACING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "export", self.trace_id, self.format, self.document,
            self.span_count,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_SPAN_STARTED = "trace.span-started"
KIND_SPAN_FINISHED = "trace.span-finished"
KIND_REJECTED = "trace.rejected"
_KINDS = (KIND_SPAN_STARTED, KIND_SPAN_FINISHED, KIND_REJECTED)


def distributed_tracing_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the distributed-tracing module."""
    if kind not in _KINDS:
        raise DistributedTracingError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise DistributedTracingError("detail must be a mapping")
    # Tag values never cross the audit boundary; ids, digests, names only.
    banned = {"tags", "attributes"}
    if any(k in detail for k in banned):
        raise DistributedTracingError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": DISTRIBUTED_TRACING_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class DistributedTracing:
    """Deterministic span/trace ledger (Jaeger/Zipkin-shaped, simulated).

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._spans: Dict[str, SpanRecord] = {}
        self._finished: Dict[str, FinishedSpan] = {}
        self._traces: Dict[str, List[str]] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internal ---------------------------------------------------------

    def _consume(self, seq: int) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(
            distributed_tracing_audit_event(kind, detail, seq)
        )

    def _reject_locked(self, seq: int, reason: str) -> None:
        self._emit(KIND_REJECTED, seq, reason=reason)

    # -- spans ------------------------------------------------------------

    def span(
        self,
        span_id: str,
        trace_id: str,
        name: str,
        seq: int,
        parent_span_id: Optional[str] = None,
        kind: str = "internal",
        tags: Optional[Mapping[str, Any]] = None,
    ) -> SpanRecord:
        """Open a span. Returns a frozen ``SpanRecord``.

        ``parent_span_id`` must name an existing span (orphan links are
        refused); root spans pass ``None``.
        """
        with self._lock:
            try:
                seq = self._consume(seq)
                span_id = _check_nonempty_str(span_id, "span_id")
                if not isinstance(trace_id, str) or not trace_id.strip():
                    raise BadTraceError("trace_id must be a non-empty string")
                trace_id = trace_id.strip()
                name = _check_nonempty_str(name, "name")
                if kind not in SPAN_KINDS:
                    raise BadSpanError(f"unknown span kind: {kind!r}")
                checked_tags = _check_tags(tags)
                if parent_span_id is not None:
                    if not isinstance(parent_span_id, str) or not parent_span_id.strip():
                        raise BadSpanError("parent_span_id must be a non-empty string")
                    parent_span_id = parent_span_id.strip()
                    if parent_span_id == span_id:
                        raise BadSpanError("span cannot be its own parent")
                    if parent_span_id not in self._spans:
                        raise UnknownSpanError(f"unknown parent span: {parent_span_id!r}")
                    parent_trace = self._spans[parent_span_id].trace_id
                    if parent_trace != trace_id:
                        raise BadSpanError("parent span belongs to another trace")
                if span_id in self._spans:
                    raise DuplicateSpanError(f"duplicate span: {span_id!r}")
            except DistributedTracingError as exc:
                self._reject_locked(seq if isinstance(seq, int) else 0, str(exc))
                raise
            digest = _pin(
                "span", span_id, trace_id, name, kind,
                parent_span_id or "", list(checked_tags), seq,
            )
            record = SpanRecord(
                span_id=span_id,
                trace_id=trace_id,
                name=name,
                kind=kind,
                parent_span_id=parent_span_id,
                tags=checked_tags,
                start_seq=seq,
                digest=digest,
            )
            self._spans[span_id] = record
            self._traces.setdefault(trace_id, []).append(span_id)
            self._emit(
                KIND_SPAN_STARTED, seq, span_id=span_id,
                trace_id=trace_id, name=name, span_kind=kind,
                parent_span_id=parent_span_id or "",
            )
            return record

    def finish_span(self, span_id: str, seq: int, status: str = "ok") -> FinishedSpan:
        """Finish an open span. Returns a frozen ``FinishedSpan``."""
        with self._lock:
            try:
                seq = self._consume(seq)
                if not isinstance(span_id, str) or not span_id.strip():
                    raise BadSpanError("span_id must be a non-empty string")
                span_id = span_id.strip()
                if status not in SPAN_STATUSES:
                    raise BadSpanError(f"unknown span status: {status!r}")
                if span_id in self._finished:
                    raise FinishedSpanError(f"span already finished: {span_id!r}")
                record = self._spans.get(span_id)
                if record is None:
                    raise UnknownSpanError(f"unknown span: {span_id!r}")
            except DistributedTracingError as exc:
                self._reject_locked(seq if isinstance(seq, int) else 0, str(exc))
                raise
            duration = seq - record.start_seq
            digest = _pin(
                "finished", span_id, record.trace_id, record.name,
                record.kind, record.parent_span_id or "", list(record.tags),
                record.start_seq, seq, duration, status,
            )
            finished = FinishedSpan(
                span_id=span_id,
                trace_id=record.trace_id,
                name=record.name,
                kind=record.kind,
                parent_span_id=record.parent_span_id,
                tags=record.tags,
                start_seq=record.start_seq,
                end_seq=seq,
                duration=duration,
                status=status,
                digest=digest,
            )
            self._finished[span_id] = finished
            self._emit(
                KIND_SPAN_FINISHED, seq, span_id=span_id,
                trace_id=record.trace_id, status=status, duration=duration,
            )
            return finished

    # -- views ------------------------------------------------------------

    def trace(self, trace_id: str, seq: int) -> TraceReport:
        """Return a frozen ``TraceReport`` for one trace.

        Pure read view: validates the seq shape, consumes nothing,
        writes no audit row.
        """
        with self._lock:
            _check_seq(seq, "seq")
            if not isinstance(trace_id, str) or not trace_id.strip():
                raise BadTraceError("trace_id must be a non-empty string")
            trace_id = trace_id.strip()
            span_ids = self._traces.get(trace_id)
            if not span_ids:
                raise UnknownTraceError(f"unknown trace: {trace_id!r}")
            ordered = tuple(
                sorted(span_ids, key=lambda sid: self._spans[sid].start_seq)
            )
            open_count = sum(1 for sid in ordered if sid not in self._finished)
            finished_count = len(ordered) - open_count
            return TraceReport(
                trace_id=trace_id,
                span_ids=ordered,
                open_spans=open_count,
                finished_spans=finished_count,
                digest=_pin(
                    "trace", trace_id, list(ordered), open_count,
                    finished_count,
                ),
            )

    def export(self, trace_id: str, seq: int, format: str = "jaeger") -> ExportRecord:
        """Render one trace as a Jaeger/Zipkin document (simulated).

        Pure read view: validates the seq shape, consumes nothing,
        writes no audit row. Durations are logical-seq units.
        """
        with self._lock:
            _check_seq(seq, "seq")
            if format not in EXPORT_FORMATS:
                raise BadFormatError(f"unknown export format: {format!r}")
            if not isinstance(trace_id, str) or not trace_id.strip():
                raise BadTraceError("trace_id must be a non-empty string")
            trace_id = trace_id.strip()
            finished = [
                self._finished[sid]
                for sid in self._traces.get(trace_id, [])
                if sid in self._finished
            ]
            if not finished:
                raise UnknownTraceError(f"unknown trace: {trace_id!r}")
            finished.sort(key=lambda f: f.start_seq)
            if format == "jaeger":
                document: Mapping[str, Any] = {
                    "traceID": trace_id,
                    "spans": [self._jaeger_span(f) for f in finished],
                    "process": {"serviceName": "northstar-agent"},
                }
            else:
                document = {
                    "traces": [
                        {
                            "traceId": trace_id,
                            "id": f.span_id,
                            "name": f.name,
                            "parentId": f.parent_span_id or "",
                            "timestamp": f.start_seq,
                            "duration": f.duration,
                            "kind": f.kind,
                            "tags": [
                                {"key": k, "value": v}
                                for k, v in f.tags
                            ],
                        }
                        for f in finished
                    ]
                }
            record = ExportRecord(
                trace_id=trace_id,
                format=format,
                document=document,
                span_count=len(finished),
                digest=_pin("export", trace_id, format, document, len(finished)),
            )
            return record

    @staticmethod
    def _jaeger_span(finished: FinishedSpan) -> Dict[str, Any]:
        span: Dict[str, Any] = {
            "spanID": finished.span_id,
            "traceID": finished.trace_id,
            "operationName": finished.name,
            "references": [],
            "startTime": finished.start_seq,
            "duration": finished.duration,
            "tags": [{"key": k, "value": v} for k, v in finished.tags],
        }
        if finished.parent_span_id:
            span["references"].append(
                {
                    "refType": "CHILD_OF",
                    "traceID": finished.trace_id,
                    "spanID": finished.parent_span_id,
                }
            )
        return span

    # -- read-only helpers ------------------------------------------------

    def span_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._spans))

    def trace_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._traces))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    dt = DistributedTracing()
    root = dt.span("root", "tr-1", "handle-request", 1, kind="server")
    child = dt.span(
        "child", "tr-1", "db-query", 2, parent_span_id="root",
        tags={"db.statement": "SELECT 1"},
    )
    dt.finish_span("child", 3)
    dt.finish_span("root", 4, status="ok")
    report = dt.trace("tr-1", 5)
    jaeger = dt.export("tr-1", 6, format="jaeger")
    zipkin = dt.export("tr-1", 7, format="zipkin")
    assert root.verify() and child.verify()
    assert report.verify() and jaeger.verify() and zipkin.verify()
    assert len(dt.audit_log()) == 4
    print("distributed-tracing OK: span, finish, trace, export, pins, audit")


if __name__ == "__main__":
    main()
