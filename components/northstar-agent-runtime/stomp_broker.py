"""STOMP (Simple Text Oriented Messaging Protocol) broker bookkeeping.

A ``STOMPBroker`` books host-declared STOMP 1.2-shaped frames as a
deterministic single-host state machine:

- ``connect(connection_id, seq, login="", passcode="", heartbeat=(0, 0))``
  pins a client connection. Duplicate ids refused fail-closed.
- ``disconnect(connection_id, seq)`` terminally closes the connection:
  subscriptions are cancelled, pending receipts flushed.
- ``send(connection_id, destination, body_digest, seq, headers=(),
  transaction=None, receipt=None)`` books one MESSAGE: payload *bytes*
  never cross this module's boundary — the frame is booked by its
  ``sha256:`` body digest only. Destinations are ``/queue/<name>`` or
  ``/topic/<name>`` shaped.
- ``subscribe(connection_id, subscription_id, destination, seq,
  ack="auto")`` pins a subscription with a pinned ack vocabulary
  (``auto``/``client``/``client-individual``); duplicate subscription
  ids on one connection refused.
- ``unsubscribe(connection_id, subscription_id, seq)`` cancels it.
- ``deliver(connection_id, seq, max_messages=10)`` returns a frozen
  ``DeliveryPage`` of the connection's next undelivered messages as
  *data*; delivery is booked so ``ack``/``nack`` can settle it.
- ``ack(connection_id, message_id, seq, transaction=None)`` /
  ``nack(...)`` settle delivered messages per the subscription's ack
  mode; unknown message ids refused fail-closed.
- ``begin``/``commit``/``abort`` book transactions: sends inside a
  transaction are staged and only become visible on ``commit``.
- A ``receipt`` header books a frozen ``ReceiptRecord`` for the frame.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin ``stomp-broker.v1``,
schema pin ``northstar.stomp-broker.v1``, ``main()`` self-check.

Honest scope: this module books *declared* frames — it performs no
network I/O, stores no payload bytes, and cannot prove a client ever
received a MESSAGE. A quiet ledger means "no known frames", never "no
traffic". ``deliver`` books the host's claim that frames were emitted;
``ack`` records the host's claim that the client processed them.
Heart-beat negotiation is booked as declared numbers only; no liveness
is measured here.
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
STOMP_BROKER_VERSION = "stomp-broker.v1"

#: Schema pin carried by records and audit events.
STOMP_BROKER_SCHEMA = "northstar.stomp-broker.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_GENESIS = "genesis"

#: Pinned ACK-mode vocabulary (STOMP 1.2 §3).
ACK_AUTO = "auto"
ACK_CLIENT = "client"
ACK_CLIENT_INDIVIDUAL = "client-individual"
_ACK_MODES = (ACK_AUTO, ACK_CLIENT, ACK_CLIENT_INDIVIDUAL)

#: Pinned transaction-isolation vocabulary (bookkeeping only).
_TXN_BOOKED = "booked"
_TXN_COMMITTED = "committed"
_TXN_ABORTED = "aborted"


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class STOMPBrokerError(ValueError):
    """Base for all STOMP-broker structural problems and refused transitions."""


class BadConnectionError(STOMPBrokerError):
    """Connection registration is malformed (bad id, heartbeat shape)."""


class DuplicateConnectionError(STOMPBrokerError):
    """A connection id is already registered."""


class UnknownConnectionError(STOMPBrokerError):
    """No connection is pinned for the requested id."""


class DisconnectedError(STOMPBrokerError):
    """The connection is terminally disconnected."""


class BadDestinationError(STOMPBrokerError):
    """Destination is malformed (must be /queue/<name> or /topic/<name>)."""


class BadHeaderError(STOMPBrokerError):
    """A frame header name or value is malformed."""


class BadBodyDigestError(STOMPBrokerError):
    """Body digest is not a ``sha256:`` + 64-hex pin."""


class DuplicateSubscriptionError(STOMPBrokerError):
    """A subscription id is already pinned on this connection."""


class UnknownSubscriptionError(STOMPBrokerError):
    """No subscription is pinned for the requested id on this connection."""


class BadAckModeError(STOMPBrokerError):
    """Ack mode is outside the pinned vocabulary."""


class UnknownMessageError(STOMPBrokerError):
    """No delivered-but-unsettled message carries the requested id."""


class DuplicateTransactionError(STOMPBrokerError):
    """A transaction id is already open on this connection."""


class UnknownTransactionError(STOMPBrokerError):
    """No open transaction carries the requested id on this connection."""


class SeqOrderError(STOMPBrokerError):
    """Caller seq did not strictly increase."""


class AuditKindError(STOMPBrokerError):
    """Unknown audit-event kind requested."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise STOMPBrokerError(f"{name} must be a non-empty string")
    return value.strip()


def _check_id(value: Any, name: str) -> str:
    value = _check_nonempty_str(value, name)
    if len(value) > 128:
        raise STOMPBrokerError(f"{name} must be <= 128 chars")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise STOMPBrokerError(f"{name} must not contain control chars")
    return value


def _check_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise BadBodyDigestError(f"{name} must be a 'sha256:' pin")
    hexpart = value[len("sha256:"):]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadBodyDigestError(f"{name} must be 'sha256:' + 64 lowercase hex")
    return value


def _check_destination(value: Any) -> str:
    value = _check_nonempty_str(value, "destination")
    if not (value.startswith("/queue/") or value.startswith("/topic/")):
        raise BadDestinationError(
            "destination must start with /queue/ or /topic/"
        )
    name = value.split("/", 2)[2]
    if not name or len(value) > 256 or any(ord(c) < 0x21 or ord(c) == 0x7F for c in value):
        raise BadDestinationError("destination name is malformed")
    return value


def _check_headers(headers: Any) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(headers, (tuple, list)):
        raise BadHeaderError("headers must be a sequence of (name, value) pairs")
    out: List[Tuple[str, str]] = []
    for pair in headers:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise BadHeaderError("each header must be a (name, value) pair")
        name, val = pair
        if not isinstance(name, str) or not name or any(
            c in name for c in ":\r\n"
        ) or any(ord(c) < 0x21 or ord(c) == 0x7F for c in name):
            raise BadHeaderError(f"bad header name: {name!r}")
        if not isinstance(val, str) or any(c in val for c in "\r\n"):
            raise BadHeaderError(f"bad header value for {name!r}")
        out.append((name, val))
    # Reserved-frame headers are banned: this module mints them.
    banned = {"message-id", "subscription", "receipt-id", "destination"}
    seen = [n.lower() for n, _ in out]
    if any(n in banned for n in seen):
        raise BadHeaderError("reserved headers are minted by the broker")
    if len(set(seen)) != len(seen):
        raise BadHeaderError("duplicate header names")
    return tuple(out)


def _check_heartbeat(value: Any) -> Tuple[int, int]:
    if not isinstance(value, (tuple, list)) or len(value) != 2:
        raise BadConnectionError("heartbeat must be a (cx, cy) pair")
    cx, cy = value
    for part in (cx, cy):
        if isinstance(part, bool) or not isinstance(part, int) or part < 0:
            raise BadConnectionError("heartbeat parts must be non-negative ints")
    return (cx, cy)


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([STOMP_BROKER_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectionRecord:
    """One pinned client connection (frozen)."""

    connection_id: str
    login: str
    heartbeat_cx: int
    heartbeat_cy: int
    seq: int
    digest: str
    schema: str = STOMP_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "connect", self.connection_id, self.login,
            self.heartbeat_cx, self.heartbeat_cy, self.seq,
        )


@dataclass(frozen=True)
class DisconnectRecord:
    """One terminal disconnect (frozen)."""

    connection_id: str
    seq: int
    digest: str
    schema: str = STOMP_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("disconnect", self.connection_id, self.seq)


@dataclass(frozen=True)
class MessageRecord:
    """One booked MESSAGE frame (frozen). Payload by digest only."""

    message_id: str
    destination: str
    body_digest: str
    headers: Tuple[Tuple[str, str], ...]
    transaction: Optional[str]
    seq: int
    digest: str
    schema: str = STOMP_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "message", self.message_id, self.destination, self.body_digest,
            [list(h) for h in self.headers], self.transaction, self.seq,
        )


@dataclass(frozen=True)
class SubscriptionRecord:
    """One pinned subscription (frozen)."""

    connection_id: str
    subscription_id: str
    destination: str
    ack_mode: str
    seq: int
    digest: str
    schema: str = STOMP_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "subscribe", self.connection_id, self.subscription_id,
            self.destination, self.ack_mode, self.seq,
        )


@dataclass(frozen=True)
class UnsubscribeRecord:
    """One cancelled subscription (frozen)."""

    connection_id: str
    subscription_id: str
    seq: int
    digest: str
    schema: str = STOMP_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "unsubscribe", self.connection_id, self.subscription_id, self.seq
        )


@dataclass(frozen=True)
class DeliveryRecord:
    """One booked delivery of a message to a connection (frozen)."""

    delivery_id: str
    connection_id: str
    subscription_id: str
    message_id: str
    seq: int
    digest: str
    schema: str = STOMP_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "deliver", self.delivery_id, self.connection_id,
            self.subscription_id, self.message_id, self.seq,
        )


@dataclass(frozen=True)
class DeliveryPage:
    """One page of delivered messages (frozen, read view)."""

    connection_id: str
    deliveries: Tuple[DeliveryRecord, ...]
    messages: Tuple[MessageRecord, ...]
    seq: int
    digest: str
    schema: str = STOMP_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "delivery-page", self.connection_id,
            [d.delivery_id for d in self.deliveries], self.seq,
        )


@dataclass(frozen=True)
class AckRecord:
    """One settled ACK/NACK verdict (frozen). Verdicts are data."""

    connection_id: str
    message_id: str
    verdict: str  # "acked" | "nacked"
    transaction: Optional[str]
    seq: int
    digest: str
    schema: str = STOMP_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "settle", self.connection_id, self.message_id,
            self.verdict, self.transaction, self.seq,
        )


@dataclass(frozen=True)
class TransactionRecord:
    """One transaction lifecycle event (frozen)."""

    connection_id: str
    transaction_id: str
    state: str  # booked | committed | aborted
    seq: int
    digest: str
    schema: str = STOMP_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "transaction", self.connection_id, self.transaction_id,
            self.state, self.seq,
        )


@dataclass(frozen=True)
class ReceiptRecord:
    """One booked RECEIPT frame (frozen)."""

    receipt_id: str
    connection_id: str
    for_frame: str
    seq: int
    digest: str
    schema: str = STOMP_BROKER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "receipt", self.receipt_id, self.connection_id,
            self.for_frame, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_CONNECTED = "stomp.connected"
KIND_DISCONNECTED = "stomp.disconnected"
KIND_SENT = "stomp.sent"
KIND_SUBSCRIBED = "stomp.subscribed"
KIND_UNSUBSCRIBED = "stomp.unsubscribed"
KIND_DELIVERED = "stomp.delivered"
KIND_SETTLED = "stomp.settled"
KIND_TXN = "stomp.transaction"
KIND_RECEIPT = "stomp.receipt"
KIND_REJECTED = "stomp.rejected"
_KINDS = (
    KIND_CONNECTED, KIND_DISCONNECTED, KIND_SENT, KIND_SUBSCRIBED,
    KIND_UNSUBSCRIBED, KIND_DELIVERED, KIND_SETTLED, KIND_TXN,
    KIND_RECEIPT, KIND_REJECTED,
)


def stomp_broker_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the STOMP-broker module."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise STOMPBrokerError("detail must be a mapping")
    # Payload bytes and credentials never cross the audit boundary.
    banned = {"body", "passcode", "headers"}
    if any(k in detail for k in banned):
        raise STOMPBrokerError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": STOMP_BROKER_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The broker
# ---------------------------------------------------------------------------


class STOMPBroker:
    """Deterministic STOMP 1.2-shaped frame ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._connections: Dict[str, ConnectionRecord] = {}
        self._disconnected: Dict[str, DisconnectRecord] = {}
        self._messages: Dict[str, MessageRecord] = {}
        self._dest_index: Dict[str, List[str]] = {}
        self._subscriptions: Dict[Tuple[str, str], SubscriptionRecord] = {}
        self._unsubscribed: List[UnsubscribeRecord] = []
        self._deliveries: Dict[str, DeliveryRecord] = {}
        self._delivered: Dict[str, List[str]] = {}  # conn -> delivery ids
        self._settled: Dict[str, AckRecord] = {}  # message_id -> settle
        self._unacked: Dict[str, List[str]] = {}  # (conn,sub) -> msg ids
        self._transactions: Dict[Tuple[str, str], TransactionRecord] = {}
        self._staged: Dict[Tuple[str, str], List[str]] = {}  # (conn,txn) -> msg ids
        self._receipts: Dict[str, ReceiptRecord] = {}
        self._audit: List[Dict[str, Any]] = []
        self._msg_counter = 0
        self._del_counter = 0

    # -- internals ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._seq}, got={seq})"
            )
        self._seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(stomp_broker_audit_event(kind, detail, seq))

    def _reject(self, seq: int, reason: str) -> None:
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _live_connection(self, connection_id: str) -> ConnectionRecord:
        conn = self._connections.get(connection_id)
        if conn is None:
            raise UnknownConnectionError(f"unknown connection: {connection_id!r}")
        if connection_id in self._disconnected:
            raise DisconnectedError(f"connection disconnected: {connection_id!r}")
        return conn

    # -- connections ----------------------------------------------------

    def connect(
        self,
        connection_id: str,
        seq: int,
        login: str = "",
        passcode: str = "",
        heartbeat: Sequence[int] = (0, 0),
    ) -> ConnectionRecord:
        """Pin a client connection (STOMP CONNECT)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                cid = _check_id(connection_id, "connection_id")
                if cid in self._connections:
                    raise DuplicateConnectionError(
                        f"connection already registered: {cid!r}"
                    )
                if not isinstance(login, str) or len(login) > 128:
                    raise BadConnectionError("login must be a str <= 128 chars")
                if not isinstance(passcode, str) or len(passcode) > 256:
                    raise BadConnectionError("passcode must be a str <= 256 chars")
                cx, cy = _check_heartbeat(heartbeat)
                rec = ConnectionRecord(
                    connection_id=cid,
                    login=login,
                    heartbeat_cx=cx,
                    heartbeat_cy=cy,
                    seq=seq,
                    digest=_pin("connect", cid, login, cx, cy, seq),
                )
                self._connections[cid] = rec
                self._emit(
                    KIND_CONNECTED, seq, connection_id=cid, login=login,
                    heartbeat=[cx, cy],
                )
                return rec
            except STOMPBrokerError as exc:
                self._reject(seq, f"{type(exc).__name__}: {exc}")
                raise

    def disconnect(self, connection_id: str, seq: int) -> DisconnectRecord:
        """Terminally close a connection (STOMP DISCONNECT)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._live_connection(connection_id)
                rec = DisconnectRecord(
                    connection_id=connection_id,
                    seq=seq,
                    digest=_pin("disconnect", connection_id, seq),
                )
                self._disconnected[connection_id] = rec
                # Cancel live subscriptions.
                for key in [k for k in self._subscriptions if k[0] == connection_id]:
                    self._unsubscribed.append(
                        UnsubscribeRecord(
                            connection_id=connection_id,
                            subscription_id=key[1],
                            seq=seq,
                            digest=_pin("unsubscribe", connection_id, key[1], seq),
                        )
                    )
                    del self._subscriptions[key]
                self._emit(KIND_DISCONNECTED, seq, connection_id=connection_id)
                return rec
            except STOMPBrokerError as exc:
                self._reject(seq, f"{type(exc).__name__}: {exc}")
                raise

    # -- messaging ------------------------------------------------------

    def send(
        self,
        connection_id: str,
        destination: str,
        body_digest: str,
        seq: int,
        headers: Sequence[Tuple[str, str]] = (),
        transaction: Optional[str] = None,
        receipt: Optional[str] = None,
    ) -> MessageRecord:
        """Book one SEND frame. Payload by digest only."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._live_connection(connection_id)
                dest = _check_destination(destination)
                digest = _check_digest(body_digest, "body_digest")
                hdrs = _check_headers(headers)
                txn: Optional[str] = None
                if transaction is not None:
                    txn = _check_id(transaction, "transaction")
                    key = (connection_id, txn)
                    trec = self._transactions.get(key)
                    if trec is None or trec.state != _TXN_BOOKED:
                        raise UnknownTransactionError(
                            f"no open transaction: {txn!r}"
                        )
                if receipt is not None:
                    _check_id(receipt, "receipt")
                self._msg_counter += 1
                mid = f"msg-{self._msg_counter}"
                rec = MessageRecord(
                    message_id=mid,
                    destination=dest,
                    body_digest=digest,
                    headers=hdrs,
                    transaction=txn,
                    seq=seq,
                    digest=_pin(
                        "message", mid, dest, digest,
                        [list(h) for h in hdrs], txn, seq,
                    ),
                )
                self._messages[mid] = rec
                if txn is not None:
                    self._staged.setdefault((connection_id, txn), []).append(mid)
                else:
                    self._dest_index.setdefault(dest, []).append(mid)
                if receipt is not None:
                    self._book_receipt(receipt, connection_id, "SEND", seq)
                self._emit(
                    KIND_SENT, seq, connection_id=connection_id,
                    message_id=mid, destination=dest, transaction=txn,
                )
                return rec
            except STOMPBrokerError as exc:
                self._reject(seq, f"{type(exc).__name__}: {exc}")
                raise

    # -- subscriptions --------------------------------------------------

    def subscribe(
        self,
        connection_id: str,
        subscription_id: str,
        destination: str,
        seq: int,
        ack: str = ACK_AUTO,
    ) -> SubscriptionRecord:
        """Pin a subscription (STOMP SUBSCRIBE)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._live_connection(connection_id)
                sid = _check_id(subscription_id, "subscription_id")
                dest = _check_destination(destination)
                if ack not in _ACK_MODES:
                    raise BadAckModeError(f"bad ack mode: {ack!r}")
                key = (connection_id, sid)
                if key in self._subscriptions:
                    raise DuplicateSubscriptionError(
                        f"subscription already pinned: {sid!r}"
                    )
                rec = SubscriptionRecord(
                    connection_id=connection_id,
                    subscription_id=sid,
                    destination=dest,
                    ack_mode=ack,
                    seq=seq,
                    digest=_pin(
                        "subscribe", connection_id, sid, dest, ack, seq
                    ),
                )
                self._subscriptions[key] = rec
                self._emit(
                    KIND_SUBSCRIBED, seq, connection_id=connection_id,
                    subscription_id=sid, destination=dest, ack_mode=ack,
                )
                return rec
            except STOMPBrokerError as exc:
                self._reject(seq, f"{type(exc).__name__}: {exc}")
                raise

    def unsubscribe(
        self, connection_id: str, subscription_id: str, seq: int
    ) -> UnsubscribeRecord:
        """Cancel a subscription (STOMP UNSUBSCRIBE)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._live_connection(connection_id)
                sid = _check_id(subscription_id, "subscription_id")
                key = (connection_id, sid)
                if key not in self._subscriptions:
                    raise UnknownSubscriptionError(
                        f"unknown subscription: {sid!r}"
                    )
                del self._subscriptions[key]
                rec = UnsubscribeRecord(
                    connection_id=connection_id,
                    subscription_id=sid,
                    seq=seq,
                    digest=_pin("unsubscribe", connection_id, sid, seq),
                )
                self._unsubscribed.append(rec)
                self._emit(
                    KIND_UNSUBSCRIBED, seq, connection_id=connection_id,
                    subscription_id=sid,
                )
                return rec
            except STOMPBrokerError as exc:
                self._reject(seq, f"{type(exc).__name__}: {exc}")
                raise

    # -- delivery & settlement ------------------------------------------

    def deliver(
        self, connection_id: str, seq: int, max_messages: int = 10
    ) -> DeliveryPage:
        """Book the next undelivered messages as a read view (data)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._live_connection(connection_id)
                if isinstance(max_messages, bool) or not isinstance(max_messages, int):
                    raise STOMPBrokerError("max_messages must be an int")
                if not 1 <= max_messages <= 1000:
                    raise STOMPBrokerError("max_messages must be in [1, 1000]")
                subs = [
                    s for (c, _), s in self._subscriptions.items()
                    if c == connection_id
                ]
                already = set(self._settled)
                for dl in self._deliveries.values():
                    if dl.connection_id == connection_id:
                        already.add(dl.message_id)
                staged = {
                    mid for mids in self._staged.values() for mid in mids
                }
                deliveries: List[DeliveryRecord] = []
                messages: List[MessageRecord] = []
                for sub in subs:
                    for mid in self._dest_index.get(sub.destination, []):
                        if mid in already or mid in staged:
                            continue
                        if len(deliveries) >= max_messages:
                            break
                        msg = self._messages[mid]
                        self._del_counter += 1
                        dl = DeliveryRecord(
                            delivery_id=f"dlv-{self._del_counter}",
                            connection_id=connection_id,
                            subscription_id=sub.subscription_id,
                            message_id=mid,
                            seq=seq,
                            digest=_pin(
                                "deliver", f"dlv-{self._del_counter}",
                                connection_id, sub.subscription_id, mid, seq,
                            ),
                        )
                        self._deliveries[dl.delivery_id] = dl
                        self._delivered.setdefault(connection_id, []).append(
                            dl.delivery_id
                        )
                        already.add(mid)
                        self._unacked.setdefault(
                            (connection_id, sub.subscription_id), []
                        ).append(mid)
                        deliveries.append(dl)
                        messages.append(msg)
                    if len(deliveries) >= max_messages:
                        break
                page = DeliveryPage(
                    connection_id=connection_id,
                    deliveries=tuple(deliveries),
                    messages=tuple(messages),
                    seq=seq,
                    digest=_pin(
                        "delivery-page", connection_id,
                        [d.delivery_id for d in deliveries], seq,
                    ),
                )
                self._emit(
                    KIND_DELIVERED, seq, connection_id=connection_id,
                    count=len(deliveries),
                )
                return page
            except STOMPBrokerError as exc:
                self._reject(seq, f"{type(exc).__name__}: {exc}")
                raise

    def ack(
        self,
        connection_id: str,
        message_id: str,
        seq: int,
        transaction: Optional[str] = None,
    ) -> AckRecord:
        """Settle one delivered message as processed (STOMP ACK)."""
        return self._settle(connection_id, message_id, "acked", seq, transaction)

    def nack(
        self,
        connection_id: str,
        message_id: str,
        seq: int,
        transaction: Optional[str] = None,
    ) -> AckRecord:
        """Settle one delivered message as rejected (STOMP NACK)."""
        return self._settle(connection_id, message_id, "nacked", seq, transaction)

    def _settle(
        self,
        connection_id: str,
        message_id: str,
        verdict: str,
        seq: int,
        transaction: Optional[str],
    ) -> AckRecord:
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._live_connection(connection_id)
                mid = _check_id(message_id, "message_id")
                txn: Optional[str] = None
                if transaction is not None:
                    txn = _check_id(transaction, "transaction")
                    key = (connection_id, txn)
                    trec = self._transactions.get(key)
                    if trec is None or trec.state != _TXN_BOOKED:
                        raise UnknownTransactionError(
                            f"no open transaction: {txn!r}"
                        )
                pending = [
                    m for dl in self._deliveries.values()
                    if dl.connection_id == connection_id and dl.message_id == mid
                    for m in [dl.message_id]
                    if m not in self._settled
                ]
                if not pending:
                    raise UnknownMessageError(
                        f"no unsettled delivery for message: {mid!r}"
                    )
                rec = AckRecord(
                    connection_id=connection_id,
                    message_id=mid,
                    verdict=verdict,
                    transaction=txn,
                    seq=seq,
                    digest=_pin(
                        "settle", connection_id, mid, verdict, txn, seq
                    ),
                )
                self._settled[mid] = rec
                for key in list(self._unacked):
                    if mid in self._unacked[key]:
                        self._unacked[key].remove(mid)
                self._emit(
                    KIND_SETTLED, seq, connection_id=connection_id,
                    message_id=mid, verdict=verdict, transaction=txn,
                )
                return rec
            except STOMPBrokerError as exc:
                self._reject(seq, f"{type(exc).__name__}: {exc}")
                raise

    # -- transactions ---------------------------------------------------

    def begin(
        self, connection_id: str, transaction_id: str, seq: int
    ) -> TransactionRecord:
        """Open a transaction (STOMP BEGIN)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._live_connection(connection_id)
                tid = _check_id(transaction_id, "transaction_id")
                key = (connection_id, tid)
                existing = self._transactions.get(key)
                if existing is not None and existing.state == _TXN_BOOKED:
                    raise DuplicateTransactionError(
                        f"transaction already open: {tid!r}"
                    )
                rec = TransactionRecord(
                    connection_id=connection_id,
                    transaction_id=tid,
                    state=_TXN_BOOKED,
                    seq=seq,
                    digest=_pin("transaction", connection_id, tid, _TXN_BOOKED, seq),
                )
                self._transactions[key] = rec
                self._emit(
                    KIND_TXN, seq, connection_id=connection_id,
                    transaction_id=tid, state=_TXN_BOOKED,
                )
                return rec
            except STOMPBrokerError as exc:
                self._reject(seq, f"{type(exc).__name__}: {exc}")
                raise

    def commit(
        self, connection_id: str, transaction_id: str, seq: int
    ) -> TransactionRecord:
        """Commit a transaction: staged messages become visible (STOMP COMMIT)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._live_connection(connection_id)
                tid = _check_id(transaction_id, "transaction_id")
                key = (connection_id, tid)
                trec = self._transactions.get(key)
                if trec is None or trec.state != _TXN_BOOKED:
                    raise UnknownTransactionError(
                        f"no open transaction: {tid!r}"
                    )
                for mid in self._staged.get(key, []):
                    msg = self._messages[mid]
                    self._dest_index.setdefault(msg.destination, []).append(mid)
                self._staged.pop(key, None)
                rec = TransactionRecord(
                    connection_id=connection_id,
                    transaction_id=tid,
                    state=_TXN_COMMITTED,
                    seq=seq,
                    digest=_pin("transaction", connection_id, tid, _TXN_COMMITTED, seq),
                )
                self._transactions[key] = rec
                self._emit(
                    KIND_TXN, seq, connection_id=connection_id,
                    transaction_id=tid, state=_TXN_COMMITTED,
                )
                return rec
            except STOMPBrokerError as exc:
                self._reject(seq, f"{type(exc).__name__}: {exc}")
                raise

    def abort(
        self, connection_id: str, transaction_id: str, seq: int
    ) -> TransactionRecord:
        """Abort a transaction: staged messages are dropped (STOMP ABORT)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                self._live_connection(connection_id)
                tid = _check_id(transaction_id, "transaction_id")
                key = (connection_id, tid)
                trec = self._transactions.get(key)
                if trec is None or trec.state != _TXN_BOOKED:
                    raise UnknownTransactionError(
                        f"no open transaction: {tid!r}"
                    )
                for mid in self._staged.get(key, []):
                    self._messages.pop(mid, None)
                self._staged.pop(key, None)
                rec = TransactionRecord(
                    connection_id=connection_id,
                    transaction_id=tid,
                    state=_TXN_ABORTED,
                    seq=seq,
                    digest=_pin("transaction", connection_id, tid, _TXN_ABORTED, seq),
                )
                self._transactions[key] = rec
                self._emit(
                    KIND_TXN, seq, connection_id=connection_id,
                    transaction_id=tid, state=_TXN_ABORTED,
                )
                return rec
            except STOMPBrokerError as exc:
                self._reject(seq, f"{type(exc).__name__}: {exc}")
                raise

    # -- receipts -------------------------------------------------------

    def _book_receipt(
        self, receipt_id: str, connection_id: str, for_frame: str, seq: int
    ) -> ReceiptRecord:
        rec = ReceiptRecord(
            receipt_id=receipt_id,
            connection_id=connection_id,
            for_frame=for_frame,
            seq=seq,
            digest=_pin("receipt", receipt_id, connection_id, for_frame, seq),
        )
        self._receipts[receipt_id] = rec
        self._emit(
            KIND_RECEIPT, seq, connection_id=connection_id,
            receipt_id=receipt_id, for_frame=for_frame,
        )
        return rec

    # -- views ----------------------------------------------------------

    def connection_record(self, connection_id: str) -> ConnectionRecord:
        """Return the pinned connection record (raises if unknown)."""
        with self._lock:
            conn = self._connections.get(connection_id)
            if conn is None:
                raise UnknownConnectionError(
                    f"unknown connection: {connection_id!r}"
                )
            return conn

    def subscription_record(
        self, connection_id: str, subscription_id: str
    ) -> SubscriptionRecord:
        """Return a pinned subscription record (raises if unknown)."""
        with self._lock:
            rec = self._subscriptions.get((connection_id, subscription_id))
            if rec is None:
                raise UnknownSubscriptionError(
                    f"unknown subscription: {subscription_id!r}"
                )
            return rec

    def message_record(self, message_id: str) -> MessageRecord:
        """Return a booked message record (raises if unknown)."""
        with self._lock:
            rec = self._messages.get(message_id)
            if rec is None:
                raise UnknownMessageError(f"unknown message: {message_id!r}")
            return rec

    def receipt_record(self, receipt_id: str) -> ReceiptRecord:
        """Return a booked receipt record (raises if unknown)."""
        with self._lock:
            rec = self._receipts.get(receipt_id)
            if rec is None:
                raise STOMPBrokerError(f"unknown receipt: {receipt_id!r}")
            return rec

    def connection_ids(self) -> List[str]:
        """Sorted ids of registered connections."""
        with self._lock:
            return sorted(self._connections)

    def live_connection_ids(self) -> List[str]:
        """Sorted ids of connections not yet disconnected."""
        with self._lock:
            return sorted(
                c for c in self._connections if c not in self._disconnected
            )

    def audit_log(self) -> List[Dict[str, Any]]:
        """Return a copy of the audit event log."""
        with self._lock:
            return list(self._audit)

    def stats(self) -> Dict[str, int]:
        """Ledger counters (pure view)."""
        with self._lock:
            return {
                "connections": len(self._connections),
                "disconnected": len(self._disconnected),
                "messages": len(self._messages),
                "subscriptions": len(self._subscriptions),
                "deliveries": len(self._deliveries),
                "settled": len(self._settled),
                "receipts": len(self._receipts),
            }

    def as_dict(self) -> Dict[str, Any]:
        """JSON-safe snapshot of ledger shape (pure view)."""
        with self._lock:
            return {
                "version": STOMP_BROKER_VERSION,
                "schema": STOMP_BROKER_SCHEMA,
                "stats": self.stats(),
                "last_seq": self._seq,
            }


def main() -> None:
    """Self-check: connect, subscribe, send, deliver, ack, disconnect."""
    b = STOMPBroker()
    b.connect("c1", 1, login="guest", heartbeat=(10000, 10000))
    b.subscribe("c1", "s1", "/queue/orders", 2, ack="client")
    digest = "sha256:" + hashlib.sha256(b"order-1").hexdigest()
    b.send("c1", "/queue/orders", digest, 3, receipt="r1")
    page = b.deliver("c1", 4)
    assert len(page.messages) == 1
    assert page.verify()
    b.ack("c1", page.messages[0].message_id, 5)
    b.disconnect("c1", 6)
    assert b.stats()["settled"] == 1
    print("stomp-broker OK: connect, subscribe, send, deliver, ack, disconnect")


if __name__ == "__main__":
    main()
