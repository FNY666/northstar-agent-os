"""Server-Sent Events (SSE) manager — simulated stream bookkeeping.

Research note (SSE literature): the W3C/WHATWG Server-Sent Events
specification models a one-way text event stream over HTTP
(``Content-Type: text/event-stream``) as a sequence of *dispatch
blocks* — each block carries optional ``event:`` (type), ``id:``
(resumption cursor), ``data:`` (payload, possibly multiline), and
``retry:`` (reconnection backoff) fields, plus ``: comment``
keep-alive lines that a client must ignore. Delivery is ordered,
clients resume via ``Last-Event-ID``, and servers emit heartbeat
comments to keep the connection alive. This module takes the
intersection for a single-host deterministic ledger:

* **Streams, not sockets**: ``stream`` books a named open stream
  (topic, optional per-stream ``retry_ms``). No HTTP is served.
* **Host-reported dispatch**: ``event`` books one ordered dispatch
  block (type, data, resumption id) into an open stream. The module
  renders the exact wire block deterministically; it sends nothing.
* **Ordered, resumable log**: events are ordered by dispatch seq;
  ``replay`` is the pure caller-driven ``Last-Event-ID`` resumption
  view. Event ids are server-assigned monotonic ``evt-N`` ids unless
  the caller supplies one.
* **Keepalive as data**: ``heartbeat`` books a comment-only block
  (the ``: ping`` keepalive pattern) — a record, not a timer.
* **Terminal close**: ``close`` terminates a stream; dispatch into a
  closed stream is refused fail-closed.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq; bool/negative
/rewind refused), RLock-guarded, fail-closed taxonomy, stdlib-only
(``canonical_json`` sibling helper behind the standard try/except
fallback), HMAC ``sha256:`` digest pins over type-tagged canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *declared* SSE dispatch
deterministically. It performs no network I/O, holds no open
connections, and cannot prove a client received anything — the host
declares every event. A booked event means "the host declared this
dispatch", never "a browser received it". Pair with a real HTTP
server and a client that honors ``Last-Event-ID`` for production.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Mapping

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
SSE_MANAGER_VERSION = "sse-manager.v1"

#: Schema pin carried by records and audit events.
SSE_MANAGER_SCHEMA = "northstar.sse-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Default SSE event type (per spec, an omitted ``event:`` field means
#: the client fires a plain ``message`` event).
EVENT_TYPE_MESSAGE = "message"

#: Audit event kinds.
KIND_STREAM_OPENED = "sse.stream-opened"
KIND_EVENT_EMITTED = "sse.event-emitted"
KIND_HEARTBEAT = "sse.heartbeat"
KIND_STREAM_CLOSED = "sse.stream-closed"
KIND_REJECTED = "sse.rejected"
_KINDS = (
    KIND_STREAM_OPENED,
    KIND_EVENT_EMITTED,
    KIND_HEARTBEAT,
    KIND_STREAM_CLOSED,
    KIND_REJECTED,
)

_DIGEST_PREFIX = "sha256:"
_AUTO_ID_PREFIX = "evt-"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SSEManagerError(ValueError):
    """Base error for the SSE manager."""


class BadStreamError(SSEManagerError):
    """Malformed stream open (bad id, topic, retry)."""


class DuplicateStreamError(SSEManagerError):
    """A stream with this id is already open."""


class UnknownStreamError(SSEManagerError):
    """No stream with this id exists."""


class ClosedStreamError(SSEManagerError):
    """The stream is closed; dispatch is refused."""


class BadEventError(SSEManagerError):
    """Malformed event dispatch (bad type, data, comment, event id)."""


class SeqOrderError(SSEManagerError):
    """Seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SSEManagerError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SSEManagerError(f"{field_name} must be a non-empty string")
    return value.strip()


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise SSEManagerError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise SSEManagerError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise SSEManagerError(f"unencodable type: {type(v).__name__}")

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    return _DIGEST_PREFIX + hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


def _check_text_field(value: Any, field_name: str, allow_empty: bool = False) -> str:
    """Validate one SSE text field: str, no CR/LF (fields are line-based)."""
    if not isinstance(value, str):
        raise SSEManagerError(f"{field_name} must be a string")
    if "\r" in value or "\n" in value:
        raise SSEManagerError(f"{field_name} must not contain CR or LF")
    if not allow_empty and not value.strip():
        raise SSEManagerError(f"{field_name} must be non-empty")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StreamRecord:
    """One pinned open SSE stream."""

    stream_id: str
    topic: str
    retry_ms: int | None
    state: str  # "open" | "closed"
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(["stream", self.stream_id, self.topic, self.retry_ms], seed),
        )


@dataclass(frozen=True)
class EventRecord:
    """One pinned dispatched SSE block (payloads by digest only)."""

    event_seq_id: str  # manager-assigned evt-N or caller-supplied id
    stream_id: str
    event_type: str
    data_digest: str  # sha256 pin over the multiline data lines
    comment: str
    dispatch_seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "event",
                    self.event_seq_id,
                    self.stream_id,
                    self.event_type,
                    self.data_digest,
                    self.comment,
                    self.dispatch_seq,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class HeartbeatRecord:
    """One pinned keepalive (comment-only block, ``: ping`` pattern)."""

    heartbeat_id: str  # hb-N
    stream_id: str
    comment: str
    dispatch_seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                ["heartbeat", self.heartbeat_id, self.stream_id,
                 self.comment, self.dispatch_seq],
                seed,
            ),
        )


@dataclass(frozen=True)
class CloseRecord:
    """One pinned terminal stream close."""

    stream_id: str
    reason: str
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(["close", self.stream_id, self.reason], seed),
        )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def sse_manager_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the SSE manager.

    Event payloads (``data``, ``comment``) are banned from the audit
    boundary — ids and digest pins only; payloads may carry PII.
    """
    if kind not in _KINDS:
        raise SSEManagerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    banned = {"data", "comment", "payload", "body", "lines"}
    if any(k in detail for k in banned):
        raise SSEManagerError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "sse_manager",
        "module_version": SSE_MANAGER_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# SSEManager
# ---------------------------------------------------------------------------


class SSEManager:
    """Deterministic SSE stream bookkeeping.

    All mutations require a caller-supplied strictly increasing ``seq``.
    Failed mutations consume their seq (ledger position stays total).
    Reads (``replay``, ``as_wire``, ``stats``) validate the seq shape but
    do not consume it and write no audit rows.
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._streams: dict[str, StreamRecord] = {}
        self._events: dict[str, EventRecord] = {}  # by event_seq_id
        self._stream_events: dict[str, list[str]] = {}  # stream_id -> event ids
        self._heartbeats: dict[str, HeartbeatRecord] = {}
        self._closed: dict[str, CloseRecord] = {}
        self._data: dict[str, tuple[str, ...]] = {}  # event id -> data lines (host-only)
        self._event_counter = 0
        self._heartbeat_counter = 0
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(sse_manager_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _open_stream(self, stream_id: str) -> StreamRecord:
        stream_id = _check_nonempty_str(stream_id, "stream_id")
        record = self._streams.get(stream_id)
        if record is None:
            raise UnknownStreamError(f"unknown stream: {stream_id!r}")
        if stream_id in self._closed:
            raise ClosedStreamError(f"stream is closed: {stream_id!r}")
        return record

    # -- streams ---------------------------------------------------------

    def stream(
        self,
        stream_id: str,
        seq: int,
        topic: str = "",
        retry_ms: int | None = None,
    ) -> StreamRecord:
        """Book an open SSE stream (the ``text/event-stream`` endpoint)."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                stream_id = _check_nonempty_str(stream_id, "stream_id")
                if not isinstance(topic, str):
                    raise BadStreamError("topic must be a string")
                if retry_ms is not None and (
                    isinstance(retry_ms, bool)
                    or not isinstance(retry_ms, int)
                    or retry_ms < 0
                ):
                    raise BadStreamError("retry_ms must be a non-negative int or None")
                if stream_id in self._streams:
                    raise DuplicateStreamError(f"stream already open: {stream_id!r}")
            except SSEManagerError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin(["stream", stream_id, topic, retry_ms], self._seed)
            record = StreamRecord(
                stream_id=stream_id,
                topic=topic,
                retry_ms=retry_ms,
                state="open",
                digest=digest,
            )
            self._streams[stream_id] = record
            self._stream_events[stream_id] = []
            self._emit(
                KIND_STREAM_OPENED,
                seq,
                stream_id=stream_id,
                topic_digest=_pin(["topic", topic], self._seed),
            )
            return record

    # -- dispatch --------------------------------------------------------

    def event(
        self,
        stream_id: str,
        data: Any,
        seq: int,
        event_type: str = EVENT_TYPE_MESSAGE,
        event_id: str | None = None,
        comment: str = "",
    ) -> EventRecord:
        """Book one ordered SSE dispatch block into an open stream.

        ``data`` is a string or a tuple/list of strings (multiline
        ``data:`` lines); the payload itself is stored host-side and
        only its digest crosses record/audit boundaries.
        """
        seq = self._next_seq(seq)
        with self._lock:
            try:
                record = self._open_stream(stream_id)
                if isinstance(data, str):
                    lines = tuple(data.split("\n"))
                elif isinstance(data, (list, tuple)) and all(
                    isinstance(d, str) for d in data
                ):
                    lines = tuple(data)
                else:
                    raise BadEventError("data must be a string or list of strings")
                if not lines or any(not ln for ln in lines):
                    raise BadEventError("data must have at least one non-empty line")
                if any("\r" in ln for ln in lines):
                    raise BadEventError("data lines must not contain CR")
                event_type = _check_text_field(event_type, "event_type")
                comment = _check_text_field(comment, "comment", allow_empty=True)
                if event_id is None:
                    self._event_counter += 1
                    event_id = f"{_AUTO_ID_PREFIX}{self._event_counter}"
                else:
                    event_id = _check_text_field(event_id, "event_id")
                    if event_id in self._events:
                        raise BadEventError(f"duplicate event id: {event_id!r}")
            except SSEManagerError as exc:
                self._reject(seq, str(exc))
                raise
            data_digest = _pin(["data", list(lines)], self._seed)
            digest = _pin(
                [
                    "event",
                    event_id,
                    stream_id,
                    event_type,
                    data_digest,
                    comment,
                    seq,
                ],
                self._seed,
            )
            evt = EventRecord(
                event_seq_id=event_id,
                stream_id=stream_id,
                event_type=event_type,
                data_digest=data_digest,
                comment=comment,
                dispatch_seq=seq,
                digest=digest,
            )
            self._events[event_id] = evt
            self._data[event_id] = lines
            self._stream_events[stream_id].append(event_id)
            self._emit(
                KIND_EVENT_EMITTED,
                seq,
                stream_id=stream_id,
                event_seq_id=event_id,
                event_type=event_type,
                data_digest=data_digest,
            )
            return evt

    def heartbeat(self, stream_id: str, seq: int, comment: str = "ping") -> HeartbeatRecord:
        """Book a keepalive comment-only block (the ``: ping`` pattern)."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                self._open_stream(stream_id)
                comment = _check_text_field(comment, "comment")
            except SSEManagerError as exc:
                self._reject(seq, str(exc))
                raise
            self._heartbeat_counter += 1
            heartbeat_id = f"hb-{self._heartbeat_counter}"
            digest = _pin(
                ["heartbeat", heartbeat_id, stream_id, comment, seq], self._seed
            )
            hb = HeartbeatRecord(
                heartbeat_id=heartbeat_id,
                stream_id=stream_id,
                comment=comment,
                dispatch_seq=seq,
                digest=digest,
            )
            self._heartbeats[heartbeat_id] = hb
            self._emit(
                KIND_HEARTBEAT,
                seq,
                stream_id=stream_id,
                heartbeat_id=heartbeat_id,
            )
            return hb

    # -- resumption ------------------------------------------------------

    def replay(
        self,
        stream_id: str,
        seq: int,
        last_event_id: str | None = None,
        limit: int = 100,
    ) -> tuple[EventRecord, ...]:
        """Pure ``Last-Event-ID`` resumption view: events after the cursor.

        Validates the seq shape, consumes nothing, writes no audit rows.
        """
        _check_seq(seq)
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise SSEManagerError("limit must be a positive int")
        stream_id = _check_nonempty_str(stream_id, "stream_id")
        ids = self._stream_events.get(stream_id)
        if ids is None:
            raise UnknownStreamError(f"unknown stream: {stream_id!r}")
        if last_event_id is not None:
            last_event_id = _check_nonempty_str(last_event_id, "last_event_id")
            if last_event_id in ids:
                ids = ids[ids.index(last_event_id) + 1 :]
            # Unknown cursor: return everything (conservative resync).
        return tuple(self._events[eid] for eid in ids[:limit])

    # -- wire rendering ---------------------------------------------------

    def as_wire(self, event_seq_id: str, seq: int) -> str:
        """Render the exact SSE wire block for a booked event (pure view).

        Validates the seq shape, consumes nothing, writes no audit rows.
        Multiline data renders as repeated ``data:`` lines; the block is
        terminated by the blank line per spec.
        """
        _check_seq(seq)
        event_seq_id = _check_nonempty_str(event_seq_id, "event_seq_id")
        evt = self._events.get(event_seq_id)
        if evt is None:
            raise BadEventError(f"unknown event id: {event_seq_id!r}")
        lines = self._data[event_seq_id]
        parts: list[str] = []
        if evt.event_type != EVENT_TYPE_MESSAGE:
            parts.append(f"event: {evt.event_type}")
        parts.append(f"id: {evt.event_seq_id}")
        for ln in lines:
            parts.append(f"data: {ln}")
        stream = self._streams.get(evt.stream_id)
        if stream is not None and stream.retry_ms is not None:
            parts.append(f"retry: {stream.retry_ms}")
        if evt.comment:
            parts.append(f": {evt.comment}")
        return "\n".join(parts) + "\n\n"

    # -- close -------------------------------------------------------------

    def close(self, stream_id: str, seq: int, reason: str = "") -> CloseRecord:
        """Terminate a stream (terminal; dispatch afterwards is refused)."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                stream_id = _check_nonempty_str(stream_id, "stream_id")
                if not isinstance(reason, str):
                    raise BadStreamError("reason must be a string")
                if stream_id not in self._streams:
                    raise UnknownStreamError(f"unknown stream: {stream_id!r}")
                if stream_id in self._closed:
                    raise ClosedStreamError(f"stream already closed: {stream_id!r}")
            except SSEManagerError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin(["close", stream_id, reason], self._seed)
            record = CloseRecord(stream_id=stream_id, reason=reason, digest=digest)
            self._closed[stream_id] = record
            self._streams[stream_id] = StreamRecord(
                stream_id=stream_id,
                topic=self._streams[stream_id].topic,
                retry_ms=self._streams[stream_id].retry_ms,
                state="closed",
                digest=self._streams[stream_id].digest,
            )
            self._emit(KIND_STREAM_CLOSED, seq, stream_id=stream_id, reason=reason)
            return record

    # -- views ---------------------------------------------------------------

    def stream_record(self, stream_id: str) -> StreamRecord:
        stream_id = _check_nonempty_str(stream_id, "stream_id")
        if stream_id not in self._streams:
            raise UnknownStreamError(f"unknown stream: {stream_id!r}")
        return self._streams[stream_id]

    def event_record(self, event_seq_id: str) -> EventRecord:
        event_seq_id = _check_nonempty_str(event_seq_id, "event_seq_id")
        if event_seq_id not in self._events:
            raise BadEventError(f"unknown event id: {event_seq_id!r}")
        return self._events[event_seq_id]

    def stream_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._streams))

    def open_ids(self) -> tuple[str, ...]:
        return tuple(sorted(s for s in self._streams if s not in self._closed))

    def event_ids(self, stream_id: str) -> tuple[str, ...]:
        stream_id = _check_nonempty_str(stream_id, "stream_id")
        if stream_id not in self._stream_events:
            raise UnknownStreamError(f"unknown stream: {stream_id!r}")
        return tuple(self._stream_events[stream_id])

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self._audit_log)

    def stats(self, seq: int) -> Mapping[str, Any]:
        """Pure view: stream/event/heartbeat counts (no seq consumed)."""
        _check_seq(seq)
        return {
            "streams": len(self._streams),
            "open": len(self.open_ids()),
            "closed": len(self._closed),
            "events": len(self._events),
            "heartbeats": len(self._heartbeats),
        }


def main() -> None:
    mgr = SSEManager(seed="selfcheck")
    s = mgr.stream("alerts", 0, topic="ops", retry_ms=3000)
    assert s.verify(seed="selfcheck") and s.state == "open"
    e = mgr.event("alerts", "cpu=91", 1)
    assert e.verify(seed="selfcheck") and e.event_seq_id == "evt-1"
    wire = mgr.as_wire("evt-1", 1)
    assert wire == "id: evt-1\ndata: cpu=91\nretry: 3000\n\n", wire
    e2 = mgr.event("alerts", ["l1", "l2"], 2, event_type="update", event_id="custom-9")
    assert mgr.as_wire("custom-9", 2).startswith("event: update\nid: custom-9\n")
    hb = mgr.heartbeat("alerts", 3)
    assert hb.verify(seed="selfcheck")
    assert len(mgr.replay("alerts", 3, last_event_id="evt-1")) == 1
    c = mgr.close("alerts", 4, reason="done")
    assert c.verify(seed="selfcheck") and mgr.stream_record("alerts").state == "closed"
    print("sse-manager OK: stream, event, wire, replay, heartbeat, close, pins, audit")


if __name__ == "__main__":
    main()
