"""SSEInterface: server-sent event stream bookkeeping for agent pipelines.

Research note: *server-sent events* (SSE) are the W3C/WHATWG one-way push
channel from server to client over HTTP — a long-lived text stream where the
server writes ``event:`` / ``data:`` / ``id:`` / ``retry:`` fields and the
browser's ``EventSource`` parses them into DOM events. Two capabilities matter
here:

* **Streams** — a named server-side channel (an SSE endpoint). Clients
  ``subscribe()``; the server ``emit()``s typed events with monotonically
  growing event ids; ``close()`` shuts the stream down.
* **Event-id resume** — SSE's ``Last-Event-ID`` header lets a reconnecting
  client resume without gaps. ``events_since(stream_id, last_event_id)``
  returns every event after a known id, the in-memory analogue.

Fail-closed rules: emitting on a closed or unknown stream, subscribing with a
duplicate subscriber id, reusing an explicit event id, or closing twice all
raise instead of silently dropping. Every event is a frozen record with a
``sha256:`` digest pin binding (stream id, event id, type, data digest, seq),
so an audit trail can later prove "this event was emitted on this stream"
without retaining the payload.

Honest scope: this is a *single-host, in-memory* stream ledger, not an HTTP
transport — there is no socket, no chunked encoding, no cross-process fan-out,
and no backpressure. ``emit()`` appends to the stream log and records
deliveries to the currently-subscribed set; it cannot prove a subscriber
*received* anything, only that the event was logged for it. A dropped process
loses everything.

Version pin: sse-interface.v1
Schema pin: northstar.sse-interface.v1
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Tuple

#: Module version.
SSE_INTERFACE_VERSION = "sse-interface.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.sse-interface.v1"

#: Default event type per the SSE spec.
DEFAULT_EVENT_TYPE = "message"


class SSEError(Exception):
    """Malformed use of the SSE contract (programming error)."""


class UnknownStreamError(SSEError):
    """Operation names a stream id the interface does not know."""


class ClosedStreamError(SSEError):
    """Operation targets a stream that has been closed."""


class DuplicateSubscriberError(SSEError):
    """A subscriber id is already registered on this stream."""


class UnknownSubscriberError(SSEError):
    """Operation names a subscriber id the stream does not know."""


class DuplicateEventIdError(SSEError):
    """An explicit event id is already used on this stream."""


class UnknownEventIdError(SSEError):
    """Resume names an event id the stream does not hold."""


class DataError(SSEError):
    """An event payload is not canonicalizable (cannot be pinned)."""


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise SSEError(f"{what} must be a non-empty str")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SSEError("seq must be a non-negative int")
    return seq


def _check_retry(retry_ms: Any) -> Any:
    if retry_ms is None:
        return None
    if isinstance(retry_ms, bool) or not isinstance(retry_ms, int) or retry_ms < 0:
        raise SSEError("retry_ms must be a non-negative int or None")
    return retry_ms


def _canonicalize(value: Any) -> str:
    """Type-tagged canonical encoding; bool != int; rejects NaN/inf/large floats.

    Mirrors the batch-5 JCS float-loss caveat: integral floats above 2^53 are
    refused rather than silently pinned through a lossy representation.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "b:true" if value else "b:false"
    if isinstance(value, int):
        return f"i:{value}"
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise DataError("NaN/inf payloads are not canonicalizable")
        if value.is_integer() and abs(value) > 2**53:
            raise DataError("integral float beyond 2^53 refused (JCS loss)")
        return f"f:{repr(value)}"
    if isinstance(value, str):
        return "s:" + json.dumps(value, ensure_ascii=False)
    if isinstance(value, (bytes, bytearray)):
        raise DataError("bytes payloads are not canonicalizable")
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda kv: str(kv[0]))
        body = ",".join(f"{_canonicalize(k)}={_canonicalize(v)}" for k, v in items)
        return "m:{" + body + "}"
    if isinstance(value, (list, tuple)):
        return "l:[" + ",".join(_canonicalize(v) for v in value) + "]"
    raise DataError(f"payload of type {type(value).__name__} is not canonicalizable")


def _digest(*parts: str) -> str:
    return "sha256:" + hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Subscription:
    """A subscriber attached to a stream."""

    stream_id: str
    subscriber_id: str
    seq: int
    schema: str = SCHEMA_PIN
    version: str = SSE_INTERFACE_VERSION

    def __post_init__(self) -> None:
        _check_str(self.stream_id, "stream_id")
        _check_str(self.subscriber_id, "subscriber_id")
        _check_seq(self.seq)

    def as_dict(self) -> dict:
        return {
            "stream_id": self.stream_id,
            "subscriber_id": self.subscriber_id,
            "seq": self.seq,
            "schema": self.schema,
            "version": self.version,
        }


@dataclass(frozen=True)
class EventRecord:
    """One emitted SSE event with a digest pin."""

    stream_id: str
    event_id: str
    event_type: str
    data: Any
    seq: int
    retry_ms: Any = None
    data_digest: str = field(init=False)
    digest: str = field(init=False)
    schema: str = SCHEMA_PIN
    version: str = SSE_INTERFACE_VERSION

    def __post_init__(self) -> None:
        _check_str(self.stream_id, "stream_id")
        _check_str(self.event_id, "event_id")
        _check_str(self.event_type, "event_type")
        _check_seq(self.seq)
        _check_retry(self.retry_ms)
        canonical = _canonicalize(self.data)
        data_digest = _digest("data", canonical)
        digest = _digest("event", self.stream_id, self.event_id, self.event_type, data_digest, str(self.seq))
        object.__setattr__(self, "data_digest", data_digest)
        object.__setattr__(self, "digest", digest)

    def verify(self) -> bool:
        """Re-derive the digest from the bound fields."""
        try:
            canonical = _canonicalize(self.data)
        except DataError:
            return False
        data_digest = _digest("data", canonical)
        expected = _digest("event", self.stream_id, self.event_id, self.event_type, data_digest, str(self.seq))
        return expected == self.digest

    def as_dict(self) -> dict:
        return {
            "stream_id": self.stream_id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "data_digest": self.data_digest,
            "digest": self.digest,
            "seq": self.seq,
            "retry_ms": self.retry_ms,
            "schema": self.schema,
            "version": self.version,
        }


@dataclass(frozen=True)
class CloseRecord:
    """A stream shutdown record."""

    stream_id: str
    seq: int
    last_event_id: Any
    event_count: int
    schema: str = SCHEMA_PIN
    version: str = SSE_INTERFACE_VERSION

    def __post_init__(self) -> None:
        _check_str(self.stream_id, "stream_id")
        _check_seq(self.seq)
        if isinstance(self.event_count, bool) or not isinstance(self.event_count, int) or self.event_count < 0:
            raise SSEError("event_count must be a non-negative int")

    def as_dict(self) -> dict:
        return {
            "stream_id": self.stream_id,
            "seq": self.seq,
            "last_event_id": self.last_event_id,
            "event_count": self.event_count,
            "schema": self.schema,
            "version": self.version,
        }


class _Stream:
    """Mutable per-stream bookkeeping (guarded by the interface lock)."""

    __slots__ = ("stream_id", "created_seq", "closed", "subscribers", "events", "next_auto_id")

    def __init__(self, stream_id: str, created_seq: int) -> None:
        self.stream_id = stream_id
        self.created_seq = created_seq
        self.closed = False
        self.subscribers: dict[str, Subscription] = {}
        self.events: list[EventRecord] = []
        self.next_auto_id = 0


class SSEInterface:
    """In-memory server-sent event stream ledger (RLock-guarded)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._streams: dict[str, _Stream] = {}

    def _live(self, stream_id: str) -> _Stream:
        stream = self._streams.get(stream_id)
        if stream is None:
            raise UnknownStreamError(f"unknown stream {stream_id!r}")
        if stream.closed:
            raise ClosedStreamError(f"stream {stream_id!r} is closed")
        return stream

    def subscribe(self, stream_id: str, subscriber_id: str, seq: int) -> Subscription:
        """Attach a subscriber; lazily creates the stream on first use."""
        _check_str(stream_id, "stream_id")
        _check_str(subscriber_id, "subscriber_id")
        _check_seq(seq)
        with self._lock:
            stream = self._streams.get(stream_id)
            if stream is None:
                stream = _Stream(stream_id, seq)
                self._streams[stream_id] = stream
            if stream.closed:
                raise ClosedStreamError(f"stream {stream_id!r} is closed")
            if subscriber_id in stream.subscribers:
                raise DuplicateSubscriberError(f"subscriber {subscriber_id!r} already on {stream_id!r}")
            sub = Subscription(stream_id=stream_id, subscriber_id=subscriber_id, seq=seq)
            stream.subscribers[subscriber_id] = sub
            return sub

    def unsubscribe(self, stream_id: str, subscriber_id: str, seq: int) -> None:
        """Detach a subscriber (closed streams refuse new traffic)."""
        _check_str(stream_id, "stream_id")
        _check_str(subscriber_id, "subscriber_id")
        _check_seq(seq)
        with self._lock:
            stream = self._streams.get(stream_id)
            if stream is None:
                raise UnknownStreamError(f"unknown stream {stream_id!r}")
            if stream.closed:
                raise ClosedStreamError(f"stream {stream_id!r} is closed")
            if subscriber_id not in stream.subscribers:
                raise UnknownSubscriberError(f"unknown subscriber {subscriber_id!r} on {stream_id!r}")
            del stream.subscribers[subscriber_id]

    def emit(
        self,
        stream_id: str,
        data: Any,
        seq: int,
        event_type: str = DEFAULT_EVENT_TYPE,
        event_id: str | None = None,
        retry_ms: int | None = None,
    ) -> EventRecord:
        """Append a typed event to the stream log with a digest pin."""
        _check_str(stream_id, "stream_id")
        _check_seq(seq)
        _check_str(event_type, "event_type")
        _check_retry(retry_ms)
        with self._lock:
            stream = self._streams.get(stream_id)
            if stream is None:
                raise UnknownStreamError(f"unknown stream {stream_id!r}")
            if stream.closed:
                raise ClosedStreamError(f"stream {stream_id!r} is closed")
            if event_id is not None:
                _check_str(event_id, "event_id")
                if any(ev.event_id == event_id for ev in stream.events):
                    raise DuplicateEventIdError(f"event id {event_id!r} already used on {stream_id!r}")
                chosen = event_id
            else:
                stream.next_auto_id += 1
                chosen = f"evt-{stream.next_auto_id}"
            record = EventRecord(
                stream_id=stream_id,
                event_id=chosen,
                event_type=event_type,
                data=data,
                seq=seq,
                retry_ms=retry_ms,
            )
            stream.events.append(record)
            return record

    def close(self, stream_id: str, seq: int) -> CloseRecord:
        """Shut a stream down; further emit/subscribe traffic is refused."""
        _check_str(stream_id, "stream_id")
        _check_seq(seq)
        with self._lock:
            stream = self._streams.get(stream_id)
            if stream is None:
                raise UnknownStreamError(f"unknown stream {stream_id!r}")
            if stream.closed:
                raise ClosedStreamError(f"stream {stream_id!r} is already closed")
            stream.closed = True
            last_event_id = stream.events[-1].event_id if stream.events else None
            return CloseRecord(
                stream_id=stream_id,
                seq=seq,
                last_event_id=last_event_id,
                event_count=len(stream.events),
            )

    def events_since(self, stream_id: str, last_event_id: str) -> Tuple[EventRecord, ...]:
        """SSE Last-Event-ID resume: every event after the named id."""
        _check_str(stream_id, "stream_id")
        _check_str(last_event_id, "last_event_id")
        with self._lock:
            stream = self._streams.get(stream_id)
            if stream is None:
                raise UnknownStreamError(f"unknown stream {stream_id!r}")
            index = None
            for i, ev in enumerate(stream.events):
                if ev.event_id == last_event_id:
                    index = i
                    break
            if index is None:
                raise UnknownEventIdError(f"event id {last_event_id!r} not on {stream_id!r}")
            return tuple(stream.events[index + 1 :])

    def last_event_id(self, stream_id: str) -> str | None:
        """Most recent event id on a stream (None when empty)."""
        _check_str(stream_id, "stream_id")
        with self._lock:
            stream = self._streams.get(stream_id)
            if stream is None:
                raise UnknownStreamError(f"unknown stream {stream_id!r}")
            return stream.events[-1].event_id if stream.events else None

    def subscribers(self, stream_id: str) -> Tuple[str, ...]:
        """Sorted subscriber ids on a stream."""
        _check_str(stream_id, "stream_id")
        with self._lock:
            stream = self._streams.get(stream_id)
            if stream is None:
                raise UnknownStreamError(f"unknown stream {stream_id!r}")
            return tuple(sorted(stream.subscribers))

    def streams(self) -> Tuple[str, ...]:
        """Sorted stream ids known to the interface."""
        with self._lock:
            return tuple(sorted(self._streams))


def sse_interface_audit_event(kind: str, seq: int, stream_id: str, **detail: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record; carries pins/ids only, never raw data."""
    allowed = {"stream-created", "subscribed", "unsubscribed", "emitted", "closed", "replayed"}
    _check_str(kind, "kind")
    _check_seq(seq)
    if kind not in allowed:
        raise SSEError(f"unknown audit kind {kind!r}")
    event = {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "module": SSE_INTERFACE_VERSION,
        "seq": seq,
        "stream_id": stream_id,
    }
    event.update(detail)
    return event


def main() -> None:
    iface = SSEInterface()
    sub = iface.subscribe("chat", "browser-1", 0)
    ev1 = iface.emit("chat", {"text": "hello"}, 1)
    ev2 = iface.emit("chat", {"text": "world"}, 2, event_type="chat-message", event_id="custom-1")
    missed = iface.events_since("chat", ev1.event_id)
    closed = iface.close("chat", 3)
    assert sub.subscriber_id == "browser-1"
    assert ev1.event_id == "evt-1" and ev1.verify()
    assert ev2.event_id == "custom-1" and ev2.verify()
    assert [e.event_id for e in missed] == ["custom-1"]
    assert closed.event_count == 2 and closed.last_event_id == "custom-1"
    try:
        iface.emit("chat", "nope", 4)
    except ClosedStreamError:
        pass
    else:  # pragma: no cover
        raise AssertionError("emit after close must refuse")
    print("sse-interface OK: subscribe, emit, resume, close, refusals")


if __name__ == "__main__":
    main()
