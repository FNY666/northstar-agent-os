"""WebSocket gateway: simulated RFC 6455 connection ledger.

Research motivation: agents that stream tool output, model tokens, or
sensor feeds to each other need a duplex channel cheaper than
request/response. WebSocket (RFC 6455) is the web's standard answer --
an HTTP Upgrade handshake followed by a framed message stream
(text/binary frames, ping/pong heartbeats, and a close handshake with
status codes). This module pins down the *gateway* side of that
contract: connection registration, frame accounting, broadcast fan-out,
and the close handshake.

This module is the connection *interface*, distinct from
``http_client.py`` (request/response bookkeeping) and
``message_queue.py`` (at-least-once pub/sub): here the load-bearing
semantics are per-connection frame ordering and connection lifecycle
(OPEN -> CLOSING -> CLOSED), not delivery guarantees.

Public API:

- ``WebSocketGateway`` -- RLock-guarded connection ledger.
  ``connect(conn_id, seq, subprotocol=None)`` registers a connection
  (returns a frozen ``Connection``). ``send(conn_id, payload, seq,
  opcode="text")`` appends an outbound frame (returns a frozen
  ``Frame`` with a ``sha256:`` digest pin). ``inject(conn_id, payload,
  seq, opcode="text")`` queues an inbound frame (host-simulated
  arrival). ``receive(conn_id, seq)`` pops the next inbound frame
  (``None`` when empty). ``broadcast(payload, seq, opcode="text")``
  fans a frame out to every OPEN connection (returns a frozen
  ``BroadcastReport``). ``close(conn_id, seq, code=1000, reason="")``
  performs the close handshake (returns a frozen ``CloseRecord``).
  ``connections()`` / ``connection(conn_id)`` views.
- ``Frame`` -- frozen record: ``conn_id``, ``opcode``, ``payload``,
  ``seq``, ``frame_no``, ``masked``, ``digest``.
- ``Connection`` / ``CloseRecord`` / ``BroadcastReport`` -- frozen
  lifecycle records with digest pins.
- ``websocket_gateway_audit_event(kind, seq, ...)`` --
  ``audit.ndjson/1``-shaped record, fixed kind vocabulary:
  ``"connected"``, ``"frame-sent"``, ``"frame-injected"``,
  ``"frame-received"``, ``"broadcast"``, ``"closed"``,
  ``"rejected"``.

Honest scope:

- Simulated -- no sockets, no real network, no handshake bytes. The
  gateway books *reported* frames; a host that lies about arrivals
  gets a perfectly consistent ledger of lies (same GIGO boundary as
  every other bookkeeping module in this tree).
- Frame digests bind content and order, not delivery: ``send()``
  records that the gateway accepted the frame for the connection,
  never that the peer received it. At-least-once/exactly-once
  semantics live in ``message_queue.py`` / ``exactly_once.py``.
- Ping/pong are ordinary frames here -- there is no timer, no
  timeout, no automatic pong. Pair with ``timeout_manager`` if a
  heartbeat policy is needed.
- Masking follows RFC 6455 directionality (client frames masked,
  server frames not): ``inject`` marks inbound frames masked, ``send``
  marks outbound frames unmasked. The mask key is a deterministic
  per-frame derivation -- it proves the bookkeeping happened, not
  confidentiality. Payloads are in-memory, never on the wire.
- Close codes follow RFC 6455 section 7.4: 1005/1006/1015 are
  reserved and refused on send; valid sent codes are 1000-1011
  (except the reserved) and 3000-4999.

Version pin: ``websocket-gateway.v1`` / schema pin
``northstar.websocket-gateway.v1``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

#: Module version.
WEBSOCKET_GATEWAY_VERSION = "websocket-gateway.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.websocket-gateway.v1"

#: Version pin carried inside audit records.
AUDIT_FORMAT = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset(
    {
        "connected",
        "frame-sent",
        "frame-injected",
        "frame-received",
        "broadcast",
        "closed",
        "rejected",
    }
)

#: Digest domain prefix; keeps pins distinct from sibling modules.
_DIGEST_DOMAIN = b"northstar-websocket-gateway.v1\x00"

#: Connection lifecycle states.
STATE_OPEN = "OPEN"
STATE_CLOSING = "CLOSING"
STATE_CLOSED = "CLOSED"

#: RFC 6455 opcodes we book.
OPCODE_TEXT = "text"
OPCODE_BINARY = "binary"
OPCODE_PING = "ping"
OPCODE_PONG = "pong"
OPCODE_CLOSE = "close"
_OPCODES = frozenset({OPCODE_TEXT, OPCODE_BINARY, OPCODE_PING, OPCODE_PONG, OPCODE_CLOSE})

#: Close codes that MUST NOT appear on the wire (RFC 6455 section 7.4).
_RESERVED_CLOSE_CODES = frozenset({1005, 1006, 1015})

#: Guardrails.
_MAX_CONN_ID_LEN = 256
_MAX_REASON_LEN = 256
_MAX_PAYLOAD_BYTES = 1024 * 1024
_MAX_CONNECTIONS = 10_000


class WebSocketGatewayError(Exception):
    """Base error for websocket gateway failures. Fail-closed, never silent."""


class DuplicateConnectionError(WebSocketGatewayError):
    """Raised when connecting an already-registered conn_id."""


class UnknownConnectionError(WebSocketGatewayError):
    """Raised when operating on a conn_id that was never connected."""


class ClosedConnectionError(WebSocketGatewayError):
    """Raised when sending on a connection that is not OPEN."""


class ProtocolError(WebSocketGatewayError):
    """Raised on RFC 6455 violations (bad opcode, reserved close code)."""


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _check_conn_id(conn_id: object) -> str:
    if isinstance(conn_id, bool) or not isinstance(conn_id, str):
        raise TypeError(f"conn_id must be str, got {type(conn_id).__name__}")
    if not conn_id:
        raise ValueError("conn_id must be non-empty")
    if len(conn_id) > _MAX_CONN_ID_LEN:
        raise ValueError(f"conn_id exceeds {_MAX_CONN_ID_LEN} chars")
    return conn_id


def _check_opcode(opcode: object) -> str:
    if isinstance(opcode, bool) or not isinstance(opcode, str):
        raise TypeError(f"opcode must be str, got {type(opcode).__name__}")
    if opcode not in _OPCODES:
        raise ProtocolError(f"unknown opcode: {opcode!r}")
    return opcode


def _check_close_code(code: object) -> int:
    if isinstance(code, bool) or not isinstance(code, int):
        raise TypeError(f"close code must be int, got {type(code).__name__}")
    if code in _RESERVED_CLOSE_CODES:
        raise ProtocolError(f"close code {code} is reserved and must not be sent")
    if not (1000 <= code <= 4999):
        raise ProtocolError(f"close code {code} outside 1000-4999")
    return code


def _canonicalize(value: Any) -> str:
    """Canonical string form for digesting. Fail-closed on ambiguity.

    Same JCS caveat as the rest of the batch line: ints are exact,
    integral floats beyond 2**53 are refused, bools encode distinctly
    from ints, dict keys must be str and are sorted.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN/inf are not canonicalizable")
        if value.is_integer() and abs(value) > 2**53:
            raise ValueError("integral float beyond 2**53 loses precision")
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, bytes):
        return "bytes:" + value.hex()
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value.keys():
            if not isinstance(k, str):
                raise TypeError("dict keys must be str")
        items = sorted(value.items(), key=lambda kv: kv[0])
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=True) + ":" + _canonicalize(v)
                for k, v in items
            )
            + "}"
        )
    raise TypeError(f"unsupported value type: {type(value).__name__}")


def _check_payload(payload: Any) -> Any:
    """Validate that a payload is canonicalizable and within size guardrail."""
    body = _canonicalize(payload)  # raises fail-closed on junk
    if len(body.encode("utf-8")) > _MAX_PAYLOAD_BYTES:
        raise ValueError(f"payload exceeds {_MAX_PAYLOAD_BYTES} bytes")
    return payload


def _check_reason(reason: object) -> str:
    if isinstance(reason, bool) or not isinstance(reason, str):
        raise TypeError(f"reason must be str, got {type(reason).__name__}")
    if len(reason) > _MAX_REASON_LEN:
        raise ValueError(f"reason exceeds {_MAX_REASON_LEN} chars")
    return reason


def _digest_frame(
    conn_id: str, opcode: str, payload: Any, seq: int, frame_no: int, masked: bool
) -> str:
    """``sha256:`` pin binding connection, opcode, payload, order, mask."""
    body = (
        json.dumps(conn_id, ensure_ascii=True)
        + "\x00"
        + opcode
        + "\x00"
        + _canonicalize(payload)
        + "\x00"
        + str(seq)
        + "\x00"
        + str(frame_no)
        + "\x00"
        + ("masked" if masked else "unmasked")
    )
    return "sha256:" + hashlib.sha256(_DIGEST_DOMAIN + body.encode("utf-8")).hexdigest()


def _mask_key(conn_id: str, frame_no: int) -> bytes:
    """Deterministic per-frame mask key (bookkeeping, not confidentiality)."""
    return hmac.new(
        _DIGEST_DOMAIN, f"{conn_id}:{frame_no}".encode("utf-8"), hashlib.sha256
    ).digest()[:4]


@dataclass(frozen=True)
class Frame:
    """One booked WebSocket frame."""

    conn_id: str
    opcode: str
    payload: Any
    seq: int
    frame_no: int
    masked: bool
    digest: str
    version: str = WEBSOCKET_GATEWAY_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "conn_id": self.conn_id,
            "opcode": self.opcode,
            "payload": self.payload,
            "seq": self.seq,
            "frame_no": self.frame_no,
            "masked": self.masked,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Connection:
    """A registered gateway connection."""

    conn_id: str
    subprotocol: Optional[str]
    seq: int
    state: str
    digest: str
    version: str = WEBSOCKET_GATEWAY_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.state not in (STATE_OPEN, STATE_CLOSING, STATE_CLOSED):
            raise ValueError(f"bad state: {self.state!r}")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "conn_id": self.conn_id,
            "subprotocol": self.subprotocol,
            "seq": self.seq,
            "state": self.state,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class CloseRecord:
    """The booked close handshake for one connection."""

    conn_id: str
    code: int
    reason: str
    seq: int
    digest: str
    version: str = WEBSOCKET_GATEWAY_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "conn_id": self.conn_id,
            "code": self.code,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class BroadcastReport:
    """Outcome of one broadcast fan-out."""

    payload_digest: str
    opcode: str
    seq: int
    delivered: Tuple[str, ...]
    skipped: Tuple[str, ...]
    digest: str
    version: str = WEBSOCKET_GATEWAY_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        for name in ("payload_digest", "digest"):
            pin = getattr(self, name)
            if not isinstance(pin, str) or not pin.startswith("sha256:"):
                raise TypeError(f"{name} must be a 'sha256:' pin")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "payload_digest": self.payload_digest,
            "opcode": self.opcode,
            "seq": self.seq,
            "delivered": list(self.delivered),
            "skipped": list(self.skipped),
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


def _digest_connection(conn_id: str, subprotocol: Optional[str], seq: int) -> str:
    body = (
        json.dumps(conn_id, ensure_ascii=True)
        + "\x00"
        + json.dumps(subprotocol, ensure_ascii=True)
        + "\x00"
        + str(seq)
    )
    return "sha256:" + hashlib.sha256(_DIGEST_DOMAIN + body.encode("utf-8")).hexdigest()


def _digest_close(conn_id: str, code: int, reason: str, seq: int) -> str:
    body = (
        json.dumps(conn_id, ensure_ascii=True)
        + "\x00"
        + str(code)
        + "\x00"
        + json.dumps(reason, ensure_ascii=True)
        + "\x00"
        + str(seq)
    )
    return "sha256:" + hashlib.sha256(_DIGEST_DOMAIN + body.encode("utf-8")).hexdigest()


def _digest_broadcast(
    payload_digest: str,
    opcode: str,
    seq: int,
    delivered: Tuple[str, ...],
    skipped: Tuple[str, ...],
) -> str:
    body = (
        payload_digest
        + "\x00"
        + opcode
        + "\x00"
        + str(seq)
        + "\x00"
        + ",".join(delivered)
        + "\x00"
        + ",".join(skipped)
    )
    return "sha256:" + hashlib.sha256(_DIGEST_DOMAIN + body.encode("utf-8")).hexdigest()


def _payload_pin(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(
        _DIGEST_DOMAIN + _canonicalize(payload).encode("utf-8")
    ).hexdigest()


class WebSocketGateway:
    """Simulated RFC 6455 gateway connection ledger.

    RLock-guarded. All time is caller-supplied integer ``seq`` -- no
    wall-clock. Connections start OPEN; ``close`` moves them to
    CLOSED (the CLOSING state is booked on the ``Frame`` with opcode
    "close" that precedes the state change). Frames are numbered per
    connection; outbound frames are unmasked (server side), inbound
    (injected) frames are masked (client side), per RFC 6455.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # conn_id -> {"record": Connection, "state": str, "out": [Frame],
        #             "in": [Frame], "frame_no": int}
        self._conns: Dict[str, Dict[str, Any]] = {}

    # -- lifecycle --------------------------------------------------------

    def connect(
        self, conn_id: object, seq: object, subprotocol: object = None
    ) -> Connection:
        """Register a connection. Duplicate conn_id raises fail-closed."""
        cid = _check_conn_id(conn_id)
        s = _check_seq(seq)
        if subprotocol is not None:
            if isinstance(subprotocol, bool) or not isinstance(subprotocol, str):
                raise TypeError(
                    f"subprotocol must be str or None, got {type(subprotocol).__name__}"
                )
            if not subprotocol:
                raise ValueError("subprotocol must be non-empty when given")
        with self._lock:
            if cid in self._conns:
                raise DuplicateConnectionError(f"already connected: {cid!r}")
            if len(self._conns) >= _MAX_CONNECTIONS:
                raise WebSocketGatewayError(
                    f"connection limit {_MAX_CONNECTIONS} reached"
                )
            record = Connection(
                conn_id=cid,
                subprotocol=subprotocol,
                seq=s,
                state=STATE_OPEN,
                digest=_digest_connection(cid, subprotocol, s),
            )
            self._conns[cid] = {
                "record": record,
                "state": STATE_OPEN,
                "out": [],
                "in": [],
                "frame_no": 0,
                "sent": 0,
                "received": 0,
            }
            return record

    def close(
        self, conn_id: object, seq: object, code: object = 1000, reason: object = ""
    ) -> CloseRecord:
        """Close handshake: books a close frame, moves the connection to CLOSED."""
        cid = _check_conn_id(conn_id)
        s = _check_seq(seq)
        c = _check_close_code(code)
        r = _check_reason(reason)
        with self._lock:
            entry = self._conns.get(cid)
            if entry is None:
                raise UnknownConnectionError(f"unknown connection: {cid!r}")
            if entry["state"] != STATE_OPEN:
                raise ClosedConnectionError(f"connection not open: {cid!r}")
            # Book the close frame first (CLOSING), then move to CLOSED.
            frame_no = entry["frame_no"]
            entry["frame_no"] += 1
            close_frame = Frame(
                conn_id=cid,
                opcode=OPCODE_CLOSE,
                payload={"code": c, "reason": r},
                seq=s,
                frame_no=frame_no,
                masked=False,
                digest=_digest_frame(cid, OPCODE_CLOSE, {"code": c, "reason": r}, s, frame_no, False),
            )
            entry["out"].append(close_frame)
            entry["sent"] += 1
            entry["state"] = STATE_CLOSED
            record = CloseRecord(
                conn_id=cid,
                code=c,
                reason=r,
                seq=s,
                digest=_digest_close(cid, c, r, s),
            )
            return record

    # -- frames -------------------------------------------------------------

    def _require_open(self, cid: str) -> Dict[str, Any]:
        entry = self._conns.get(cid)
        if entry is None:
            raise UnknownConnectionError(f"unknown connection: {cid!r}")
        if entry["state"] != STATE_OPEN:
            raise ClosedConnectionError(f"connection not open: {cid!r}")
        return entry

    def send(
        self, conn_id: object, payload: Any, seq: object, opcode: object = OPCODE_TEXT
    ) -> Frame:
        """Append an outbound (server-side, unmasked) frame to an OPEN connection."""
        cid = _check_conn_id(conn_id)
        s = _check_seq(seq)
        op = _check_opcode(opcode)
        _check_payload(payload)
        with self._lock:
            entry = self._require_open(cid)
            frame_no = entry["frame_no"]
            entry["frame_no"] += 1
            frame = Frame(
                conn_id=cid,
                opcode=op,
                payload=payload,
                seq=s,
                frame_no=frame_no,
                masked=False,
                digest=_digest_frame(cid, op, payload, s, frame_no, False),
            )
            entry["out"].append(frame)
            entry["sent"] += 1
            return frame

    def inject(
        self, conn_id: object, payload: Any, seq: object, opcode: object = OPCODE_TEXT
    ) -> Frame:
        """Queue an inbound (client-side, masked) frame -- simulates network arrival."""
        cid = _check_conn_id(conn_id)
        s = _check_seq(seq)
        op = _check_opcode(opcode)
        _check_payload(payload)
        with self._lock:
            entry = self._require_open(cid)
            frame_no = entry["frame_no"]
            entry["frame_no"] += 1
            frame = Frame(
                conn_id=cid,
                opcode=op,
                payload=payload,
                seq=s,
                frame_no=frame_no,
                masked=True,
                digest=_digest_frame(cid, op, payload, s, frame_no, True),
            )
            entry["in"].append(frame)
            return frame

    def receive(self, conn_id: object, seq: object) -> Optional[Frame]:
        """Pop the next inbound frame, or ``None`` when the queue is empty.

        ``seq`` is the audit seq for the pop action; it does not order
        frames (frames are ordered by ``frame_no``).
        """
        cid = _check_conn_id(conn_id)
        _check_seq(seq)
        with self._lock:
            entry = self._conns.get(cid)
            if entry is None:
                raise UnknownConnectionError(f"unknown connection: {cid!r}")
            if not entry["in"]:
                return None
            frame = entry["in"].pop(0)
            entry["received"] += 1
            return frame

    def ping(self, conn_id: object, seq: object, payload: Any = "") -> Frame:
        """Book a ping frame (no timer, no automatic pong -- see module docstring)."""
        return self.send(conn_id, payload, seq, opcode=OPCODE_PING)

    def pong(self, conn_id: object, seq: object, payload: Any = "") -> Frame:
        """Book a pong frame in reply to a ping."""
        return self.send(conn_id, payload, seq, opcode=OPCODE_PONG)

    def broadcast(
        self, payload: Any, seq: object, opcode: object = OPCODE_TEXT
    ) -> BroadcastReport:
        """Fan one frame out to every OPEN connection.

        Closed connections are skipped (named in ``skipped``), never
        failed -- a broadcast is best-effort by definition.
        """
        s = _check_seq(seq)
        op = _check_opcode(opcode)
        _check_payload(payload)
        pin = _payload_pin(payload)
        with self._lock:
            delivered: List[str] = []
            skipped: List[str] = []
            for cid in sorted(self._conns):
                entry = self._conns[cid]
                if entry["state"] != STATE_OPEN:
                    skipped.append(cid)
                    continue
                frame_no = entry["frame_no"]
                entry["frame_no"] += 1
                entry["out"].append(
                    Frame(
                        conn_id=cid,
                        opcode=op,
                        payload=payload,
                        seq=s,
                        frame_no=frame_no,
                        masked=False,
                        digest=_digest_frame(cid, op, payload, s, frame_no, False),
                    )
                )
                entry["sent"] += 1
                delivered.append(cid)
            report = BroadcastReport(
                payload_digest=pin,
                opcode=op,
                seq=s,
                delivered=tuple(delivered),
                skipped=tuple(skipped),
                digest=_digest_broadcast(
                    pin, op, s, tuple(delivered), tuple(skipped)
                ),
            )
            return report

    # -- views --------------------------------------------------------------

    def connection(self, conn_id: object) -> Connection:
        """Return the connection record (state reflects the latest transition)."""
        cid = _check_conn_id(conn_id)
        with self._lock:
            entry = self._conns.get(cid)
            if entry is None:
                raise UnknownConnectionError(f"unknown connection: {cid!r}")
            record = entry["record"]
            if record.state != entry["state"]:
                record = Connection(
                    conn_id=record.conn_id,
                    subprotocol=record.subprotocol,
                    seq=record.seq,
                    state=entry["state"],
                    digest=record.digest,
                )
            return record

    def connections(self) -> Tuple[str, ...]:
        """Sorted conn_ids, open and closed alike."""
        with self._lock:
            return tuple(sorted(self._conns))

    def outbound(self, conn_id: object) -> Tuple[Frame, ...]:
        """Outbound frames booked for a connection, in order."""
        cid = _check_conn_id(conn_id)
        with self._lock:
            entry = self._conns.get(cid)
            if entry is None:
                raise UnknownConnectionError(f"unknown connection: {cid!r}")
            return tuple(entry["out"])

    def stats(self, conn_id: object) -> Dict[str, Any]:
        """Per-connection counters."""
        cid = _check_conn_id(conn_id)
        with self._lock:
            entry = self._conns.get(cid)
            if entry is None:
                raise UnknownConnectionError(f"unknown connection: {cid!r}")
            return {
                "conn_id": cid,
                "state": entry["state"],
                "frames_sent": entry["sent"],
                "frames_received": entry["received"],
                "inbound_queued": len(entry["in"]),
            }

    def mask_key(self, conn_id: object, frame_no: object) -> bytes:
        """Deterministic mask key for a frame (bookkeeping, not confidentiality)."""
        cid = _check_conn_id(conn_id)
        if isinstance(frame_no, bool) or not isinstance(frame_no, int):
            raise TypeError(
                f"frame_no must be int, got {type(frame_no).__name__}"
            )
        if frame_no < 0:
            raise ValueError("frame_no must be non-negative")
        return _mask_key(cid, frame_no)


def websocket_gateway_audit_event(kind: object, seq: object, **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for a gateway event.

    ``detail`` carries pins/ids/counts only -- never raw payloads.
    """
    if isinstance(kind, bool) or not isinstance(kind, str):
        raise TypeError(f"kind must be str, got {type(kind).__name__}")
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown audit kind: {kind!r}")
    s = _check_seq(seq)
    for key in detail:
        if not isinstance(key, str):
            raise TypeError("audit detail keys must be str")
    return {
        "format": AUDIT_FORMAT,
        "kind": kind,
        "seq": s,
        "module": WEBSOCKET_GATEWAY_VERSION,
        "schema": SCHEMA_PIN,
        "detail": dict(detail),
    }


def main() -> None:
    gw = WebSocketGateway()
    gw.connect("c1", 0)
    gw.connect("c2", 1, subprotocol="chat")
    f = gw.send("c1", "hello", 2)
    assert f.opcode == "text" and not f.masked
    gw.inject("c1", "hi back", 3, opcode="binary")
    r = gw.receive("c1", 4)
    assert r is not None and r.masked and r.opcode == "binary"
    rep = gw.broadcast("news", 5)
    assert rep.delivered == ("c1", "c2") and rep.skipped == ()
    gw.close("c2", 6, code=1000, reason="done")
    rep2 = gw.broadcast("after", 7)
    assert rep2.delivered == ("c1",) and rep2.skipped == ("c2",)
    try:
        gw.send("c2", "x", 8)
    except ClosedConnectionError:
        pass
    else:
        raise AssertionError("send on closed conn must fail")
    print("websocket-gateway OK: connect, send, inject/receive, broadcast, close")


if __name__ == "__main__":
    main()
