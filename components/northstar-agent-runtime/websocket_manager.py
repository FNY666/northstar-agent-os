"""WebSocket connection, room, and broadcast bookkeeping (Socket.io-shaped).

A ``WebSocketManager`` books host-reported WebSocket connection lifecycle,
room membership, and broadcast/send decisions as a deterministic
single-host state machine:

- ``connect(connection_id, seq, client="", origin="")`` pins a connection
  in ``connected`` state: frozen ``ConnectionRecord`` with a ``sha256:``
  digest pin. Duplicate ids are refused fail-closed.
- ``disconnect(connection_id, seq, reason="")`` closes the connection:
  terminal frozen ``DisconnectRecord``; the connection leaves every room
  it held. Double-disconnect raises ``TerminalConnectionError``.
- ``room(connection_id, room_name, seq)`` books a room join: frozen
  ``RoomMembership`` (``mem-N`` ids); ``leave(connection_id, room_name,
  seq)`` books a room departure: frozen ``LeaveRecord``. Room names are
  a pinned shape (non-empty, no whitespace, <= 128 chars).
- ``broadcast(room_name, message_digest, seq, exclude=())`` books a
  broadcast *decision* to every connected member of the room: frozen
  ``BroadcastRecord`` (``bc-N`` ids) listing the recipient connection
  ids as data. The message itself never enters a record — only a
  ``sha256:`` ``message_digest``.
- ``send(connection_id, message_digest, seq)`` books a direct message
  decision to one connection: frozen ``SendRecord``.

All state mutations take caller-supplied strictly increasing int ``seq``
(monotonic logical time); no wall-clock is read anywhere. Failed
mutations consume their seq (batch-21 discipline). Host-injectable
``emitter`` (default: deterministic in-memory recorder) lets the host
wire real delivery; delivery outcomes are booked as data, never raised.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``websocket-manager.v1``, schema pin ``northstar.websocket-manager.v1``,
``main()`` self-check.

Honest scope: this module books *host-reported* connection state and
*delivery decisions* — it cannot prove a socket is actually open, that a
broadcast reached every recipient, or that an unreported connection
exists. A ``BroadcastRecord`` means "the host declared this broadcast
to these recipients", never wire truth. Pair with a real WebSocket
server for production.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
WEBSOCKET_MANAGER_VERSION = "websocket-manager.v1"

#: Schema pin carried by records and audit events.
WEBSOCKET_MANAGER_SCHEMA = "northstar.websocket-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_GENESIS = "genesis"

#: Max length for a room name.
MAX_ROOM_LEN = 128

#: Pinned disconnect reason vocabulary.
REASON_CLOSE = "close"
REASON_TIMEOUT = "timeout"
REASON_ERROR = "error"
REASON_SERVER = "server"
REASONS = (REASON_CLOSE, REASON_TIMEOUT, REASON_ERROR, REASON_SERVER)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class WebSocketManagerError(ValueError):
    """Base for all websocket-manager structural problems and refused transitions."""


class BadConnectionError(WebSocketManagerError):
    """Connection definition is malformed (bad id, client, origin)."""


class DuplicateConnectionError(WebSocketManagerError):
    """A connection id is already registered."""


class UnknownConnectionError(WebSocketManagerError):
    """No connection is pinned for the requested id."""


class TerminalConnectionError(WebSocketManagerError):
    """The connection is already disconnected (terminal)."""


class BadRoomError(WebSocketManagerError):
    """Room name is malformed."""


class UnknownRoomError(WebSocketManagerError):
    """No such room has any membership."""


class DuplicateMembershipError(WebSocketManagerError):
    """The connection is already a member of the room."""


class UnknownMembershipError(WebSocketManagerError):
    """The connection is not a member of the room."""


class BadDigestError(WebSocketManagerError):
    """Message digest is malformed (must be sha256: + 64 hex)."""


class BadEmitterError(WebSocketManagerError):
    """Emitter callback misbehaved (raised) during a send."""


class SeqOrderError(WebSocketManagerError):
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
        raise BadConnectionError(f"{name} must be a non-empty string")
    return value.strip()


def _check_room(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_ROOM_LEN:
        raise BadRoomError(
            f"room_name must be a non-empty string of at most {MAX_ROOM_LEN} chars"
        )
    if any(ch.isspace() for ch in value):
        raise BadRoomError("room_name must not contain whitespace")
    return value


def _check_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise BadDigestError(f"{name} must be a 'sha256:' + 64-hex digest")
    hexpart = value[len("sha256:"):]
    if len(hexpart) != 64 or any(c not in "0123456789abcdefABCDEF" for c in hexpart):
        raise BadDigestError(f"{name} must be a 'sha256:' + 64-hex digest")
    return value


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([WEBSOCKET_MANAGER_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectionRecord:
    """One pinned connection (frozen)."""

    connection_id: str
    client: str
    origin: str
    seq: int
    digest: str
    schema: str = WEBSOCKET_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "connection", self.connection_id, self.client, self.origin, self.seq
        )


@dataclass(frozen=True)
class DisconnectRecord:
    """One terminal disconnect (frozen)."""

    connection_id: str
    reason: str
    rooms_released: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = WEBSOCKET_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "disconnect", self.connection_id, self.reason,
            list(self.rooms_released), self.seq,
        )


@dataclass(frozen=True)
class RoomMembership:
    """One room join (frozen)."""

    membership_id: str
    connection_id: str
    room_name: str
    seq: int
    digest: str
    schema: str = WEBSOCKET_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "membership", self.membership_id, self.connection_id,
            self.room_name, self.seq,
        )


@dataclass(frozen=True)
class LeaveRecord:
    """One room departure (frozen)."""

    membership_id: str
    connection_id: str
    room_name: str
    seq: int
    digest: str
    schema: str = WEBSOCKET_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "leave", self.membership_id, self.connection_id,
            self.room_name, self.seq,
        )


@dataclass(frozen=True)
class BroadcastRecord:
    """One booked broadcast decision (frozen). ``message_digest`` only."""

    broadcast_id: str
    room_name: str
    message_digest: str
    recipients: Tuple[str, ...]
    delivered: Tuple[str, ...]
    failed: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = WEBSOCKET_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "broadcast", self.broadcast_id, self.room_name,
            self.message_digest, list(self.recipients),
            list(self.delivered), list(self.failed), self.seq,
        )


@dataclass(frozen=True)
class SendRecord:
    """One booked direct-send decision (frozen). ``message_digest`` only."""

    send_id: str
    connection_id: str
    message_digest: str
    delivered: bool
    seq: int
    digest: str
    schema: str = WEBSOCKET_MANAGER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "send", self.send_id, self.connection_id,
            self.message_digest, self.delivered, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_CONNECTED = "websocket.connected"
KIND_DISCONNECTED = "websocket.disconnected"
KIND_ROOM_JOINED = "websocket.room-joined"
KIND_ROOM_LEFT = "websocket.room-left"
KIND_BROADCAST = "websocket.broadcast"
KIND_SENT = "websocket.sent"
KIND_REJECTED = "websocket.rejected"
_KINDS = (
    KIND_CONNECTED, KIND_DISCONNECTED, KIND_ROOM_JOINED, KIND_ROOM_LEFT,
    KIND_BROADCAST, KIND_SENT, KIND_REJECTED,
)


def websocket_manager_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the websocket-manager module."""
    if kind not in _KINDS:
        raise WebSocketManagerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise WebSocketManagerError("detail must be a mapping")
    # Message payloads never cross the audit boundary; digests and ids only.
    banned = {"payload", "message", "body", "frame"}
    if any(k in detail for k in banned):
        raise WebSocketManagerError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": WEBSOCKET_MANAGER_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The manager
# ---------------------------------------------------------------------------


def _default_emitter(
    connection_id: str, message_digest: str
) -> bool:
    """Deterministic in-memory delivery stand-in (always succeeds)."""
    return True


class WebSocketManager:
    """Deterministic WebSocket connection/room/broadcast bookkeeping.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(
        self,
        emitter: Optional[Callable[[str, str], bool]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._emitter = emitter if emitter is not None else _default_emitter
        self._seq = -1
        self._connections: Dict[str, ConnectionRecord] = {}
        self._disconnected: Dict[str, DisconnectRecord] = {}
        self._memberships: Dict[Tuple[str, str], RoomMembership] = {}
        self._members: Dict[str, List[str]] = {}
        self._broadcasts: Dict[str, BroadcastRecord] = {}
        self._sends: Dict[str, SendRecord] = {}
        self._mem_counter = 0
        self._bc_counter = 0
        self._send_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ----------------------------------------------------

    def _take_seq(self, seq: int) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._seq}, got={seq})"
            )
        self._seq = seq
        return seq

    def _emit(self, kind: str, detail: Mapping[str, Any], seq: int) -> None:
        self._audit.append(
            websocket_manager_audit_event(kind, detail, seq)
        )

    def _reject(self, reason: str, seq: int) -> None:
        self._emit(KIND_REJECTED, {"reason": reason}, seq)

    def _deliver(self, connection_id: str, message_digest: str) -> bool:
        try:
            return bool(self._emitter(connection_id, message_digest))
        except Exception as exc:  # noqa: BLE001 - fail-closed on emitter
            raise BadEmitterError(
                f"emitter raised for {connection_id!r}: {exc}"
            ) from exc

    # -- lifecycle ----------------------------------------------------

    def connect(
        self, connection_id: str, seq: int, client: str = "",
        origin: str = ""
    ) -> ConnectionRecord:
        """Pin a new connection (frozen record)."""
        with self._lock:
            seq = self._take_seq(seq)
            cid = _check_nonempty_str(connection_id, "connection_id")
            if cid in self._connections or cid in self._disconnected:
                self._reject("duplicate-connection", seq)
                raise DuplicateConnectionError(
                    f"connection id already registered: {cid!r}"
                )
            if not isinstance(client, str) or not isinstance(origin, str):
                self._reject("bad-connection", seq)
                raise BadConnectionError("client/origin must be strings")
            rec = ConnectionRecord(
                connection_id=cid,
                client=client,
                origin=origin,
                seq=seq,
                digest=_pin("connection", cid, client, origin, seq),
            )
            self._connections[cid] = rec
            self._emit(
                KIND_CONNECTED,
                {"connection_id": cid, "digest": rec.digest},
                seq,
            )
            return rec

    def disconnect(
        self, connection_id: str, seq: int, reason: str = REASON_CLOSE
    ) -> DisconnectRecord:
        """Terminally close a connection; it leaves every room it held."""
        with self._lock:
            seq = self._take_seq(seq)
            cid = _check_nonempty_str(connection_id, "connection_id")
            if cid in self._disconnected:
                self._reject("already-disconnected", seq)
                raise TerminalConnectionError(
                    f"connection already disconnected: {cid!r}"
                )
            if cid not in self._connections:
                self._reject("unknown-connection", seq)
                raise UnknownConnectionError(f"unknown connection: {cid!r}")
            if reason not in REASONS:
                self._reject("bad-reason", seq)
                raise WebSocketManagerError(
                    f"reason must be one of {REASONS}"
                )
            released = tuple(
                sorted(
                    room for (c, room) in self._memberships if c == cid
                )
            )
            for room in released:
                del self._memberships[(cid, room)]
                self._members[room] = [
                    m for m in self._members.get(room, []) if m != cid
                ]
                if not self._members[room]:
                    del self._members[room]
            rec = DisconnectRecord(
                connection_id=cid,
                reason=reason,
                rooms_released=released,
                seq=seq,
                digest=_pin("disconnect", cid, reason, list(released), seq),
            )
            del self._connections[cid]
            self._disconnected[cid] = rec
            self._emit(
                KIND_DISCONNECTED,
                {
                    "connection_id": cid,
                    "reason": reason,
                    "digest": rec.digest,
                },
                seq,
            )
            return rec

    # -- rooms --------------------------------------------------------

    def room(
        self, connection_id: str, room_name: str, seq: int
    ) -> RoomMembership:
        """Book a room join (frozen membership)."""
        with self._lock:
            seq = self._take_seq(seq)
            cid = _check_nonempty_str(connection_id, "connection_id")
            room = _check_room(room_name)
            if cid not in self._connections:
                self._reject("unknown-connection", seq)
                if cid in self._disconnected:
                    raise TerminalConnectionError(
                        f"connection disconnected: {cid!r}"
                    )
                raise UnknownConnectionError(f"unknown connection: {cid!r}")
            if (cid, room) in self._memberships:
                self._reject("duplicate-membership", seq)
                raise DuplicateMembershipError(
                    f"already a member of {room!r}: {cid!r}"
                )
            self._mem_counter += 1
            mid = f"mem-{self._mem_counter}"
            rec = RoomMembership(
                membership_id=mid,
                connection_id=cid,
                room_name=room,
                seq=seq,
                digest=_pin("membership", mid, cid, room, seq),
            )
            self._memberships[(cid, room)] = rec
            self._members.setdefault(room, []).append(cid)
            self._emit(
                KIND_ROOM_JOINED,
                {
                    "membership_id": mid,
                    "connection_id": cid,
                    "room_name": room,
                    "digest": rec.digest,
                },
                seq,
            )
            return rec

    def leave(
        self, connection_id: str, room_name: str, seq: int
    ) -> LeaveRecord:
        """Book a room departure (frozen record)."""
        with self._lock:
            seq = self._take_seq(seq)
            cid = _check_nonempty_str(connection_id, "connection_id")
            room = _check_room(room_name)
            mem = self._memberships.get((cid, room))
            if mem is None:
                self._reject("unknown-membership", seq)
                raise UnknownMembershipError(
                    f"not a member of {room!r}: {cid!r}"
                )
            rec = LeaveRecord(
                membership_id=mem.membership_id,
                connection_id=cid,
                room_name=room,
                seq=seq,
                digest=_pin("leave", mem.membership_id, cid, room, seq),
            )
            del self._memberships[(cid, room)]
            self._members[room] = [
                m for m in self._members.get(room, []) if m != cid
            ]
            if not self._members[room]:
                del self._members[room]
            self._emit(
                KIND_ROOM_LEFT,
                {
                    "membership_id": mem.membership_id,
                    "connection_id": cid,
                    "room_name": room,
                    "digest": rec.digest,
                },
                seq,
            )
            return rec

    # -- messaging ----------------------------------------------------

    def broadcast(
        self, room_name: str, message_digest: str, seq: int,
        exclude: Sequence[str] = (),
    ) -> BroadcastRecord:
        """Book a broadcast decision to a room's connected members.

        Delivery outcomes are booked as data (``delivered``/``failed``
        recipient lists); a raising emitter fails closed.
        """
        with self._lock:
            seq = self._take_seq(seq)
            room = _check_room(room_name)
            digest = _check_digest(message_digest, "message_digest")
            excluded = set()
            for e in exclude:
                excluded.add(_check_nonempty_str(e, "exclude entry"))
            members = self._members.get(room)
            if members is None:
                self._reject("unknown-room", seq)
                raise UnknownRoomError(f"no such room: {room!r}")
            recipients = tuple(
                sorted(m for m in members if m not in excluded)
            )
            delivered: List[str] = []
            failed: List[str] = []
            for cid in recipients:
                if self._deliver(cid, digest):
                    delivered.append(cid)
                else:
                    failed.append(cid)
            self._bc_counter += 1
            bid = f"bc-{self._bc_counter}"
            rec = BroadcastRecord(
                broadcast_id=bid,
                room_name=room,
                message_digest=digest,
                recipients=recipients,
                delivered=tuple(delivered),
                failed=tuple(failed),
                seq=seq,
                digest=_pin(
                    "broadcast", bid, room, digest, list(recipients),
                    delivered, failed, seq,
                ),
            )
            self._broadcasts[bid] = rec
            self._emit(
                KIND_BROADCAST,
                {
                    "broadcast_id": bid,
                    "room_name": room,
                    "message_digest": digest,
                    "digest": rec.digest,
                },
                seq,
            )
            return rec

    def send(
        self, connection_id: str, message_digest: str, seq: int
    ) -> SendRecord:
        """Book a direct-send decision to one connection.

        Delivery outcome is booked as data; a raising emitter fails
        closed.
        """
        with self._lock:
            seq = self._take_seq(seq)
            cid = _check_nonempty_str(connection_id, "connection_id")
            digest = _check_digest(message_digest, "message_digest")
            if cid not in self._connections:
                self._reject("unknown-connection", seq)
                if cid in self._disconnected:
                    raise TerminalConnectionError(
                        f"connection disconnected: {cid!r}"
                    )
                raise UnknownConnectionError(f"unknown connection: {cid!r}")
            delivered = self._deliver(cid, digest)
            self._send_counter += 1
            sid = f"send-{self._send_counter}"
            rec = SendRecord(
                send_id=sid,
                connection_id=cid,
                message_digest=digest,
                delivered=delivered,
                seq=seq,
                digest=_pin("send", sid, cid, digest, delivered, seq),
            )
            self._sends[sid] = rec
            self._emit(
                KIND_SENT,
                {
                    "send_id": sid,
                    "connection_id": cid,
                    "message_digest": digest,
                    "digest": rec.digest,
                },
                seq,
            )
            return rec

    # -- views --------------------------------------------------------

    def connection(self, connection_id: str) -> ConnectionRecord:
        """Return a pinned connection record."""
        with self._lock:
            rec = self._connections.get(connection_id)
            if rec is None:
                if connection_id in self._disconnected:
                    raise TerminalConnectionError(
                        f"connection disconnected: {connection_id!r}"
                    )
                raise UnknownConnectionError(
                    f"unknown connection: {connection_id!r}"
                )
            return rec

    def connection_ids(self) -> Tuple[str, ...]:
        """Sorted ids of currently connected connections."""
        with self._lock:
            return tuple(sorted(self._connections))

    def is_connected(self, connection_id: str) -> bool:
        """Whether the id currently holds a live connection."""
        with self._lock:
            return connection_id in self._connections

    def members(self, room_name: str) -> Tuple[str, ...]:
        """Sorted connected member ids of a room."""
        with self._lock:
            room = _check_room(room_name)
            return tuple(sorted(self._members.get(room, [])))

    def rooms_of(self, connection_id: str) -> Tuple[str, ...]:
        """Sorted rooms the connection currently holds."""
        with self._lock:
            return tuple(
                sorted(
                    room for (c, room) in self._memberships
                    if c == connection_id
                )
            )

    def rooms(self) -> Tuple[str, ...]:
        """Sorted names of rooms with at least one member."""
        with self._lock:
            return tuple(sorted(self._members))

    def broadcast_record(self, broadcast_id: str) -> BroadcastRecord:
        """Return a booked broadcast record."""
        with self._lock:
            rec = self._broadcasts.get(broadcast_id)
            if rec is None:
                raise WebSocketManagerError(
                    f"unknown broadcast: {broadcast_id!r}"
                )
            return rec

    def stats(self) -> Dict[str, int]:
        """Counts of connections, rooms, memberships, broadcasts, sends."""
        with self._lock:
            return {
                "connections": len(self._connections),
                "disconnected": len(self._disconnected),
                "rooms": len(self._members),
                "memberships": len(self._memberships),
                "broadcasts": len(self._broadcasts),
                "sends": len(self._sends),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events booked so far (oldest first)."""
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> Dict[str, Any]:
        """JSON-safe snapshot (pins and ids only)."""
        with self._lock:
            return {
                "version": WEBSOCKET_MANAGER_VERSION,
                "schema": WEBSOCKET_MANAGER_SCHEMA,
                "seq": self._seq,
                "connections": [c.connection_id for c in
                                self._connections.values()],
                "rooms": sorted(self._members),
                "stats": self.stats(),
            }


def main() -> None:
    mgr = WebSocketManager()
    mgr.connect("c1", 1, client="web")
    mgr.connect("c2", 2, client="mobile")
    mgr.room("c1", "lobby", 3)
    mgr.room("c2", "lobby", 4)
    digest = "sha256:" + "ab" * 32
    bc = mgr.broadcast("lobby", digest, 5)
    assert bc.recipients == ("c1", "c2"), bc
    mgr.send("c1", digest, 6)
    mgr.leave("c1", "lobby", 7)
    d = mgr.disconnect("c1", 8, reason=REASON_CLOSE)
    assert d.rooms_released == (), d
    assert mgr.is_connected("c2")
    print("websocket-manager OK: connect, room, broadcast, send, leave, disconnect")


if __name__ == "__main__":
    main()
