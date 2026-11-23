"""ZeroMQ messaging patterns bookkeeping (simulated).

Interface:
    ZeroMQPatterns.socket(socket_id, pattern, seq) -> sealed SocketRecord
        (pattern: "req" | "rep" | "pub" | "sub" | "push" | "pull")
    ZeroMQPatterns.connect(socket_id, peer_id, seq) -> sealed ConnectionRecord
        (req<->rep and push<->pull pairing; pub/sub use subscribe instead)
    ZeroMQPatterns.subscribe(socket_id, topic, seq) -> sealed SubscriptionRecord
        (sub sockets only; ZeroMQ prefix matching)
    ZeroMQPatterns.reqrep(client_id, server_id, request_digest, seq,
                           handler=None) -> sealed ExchangeRecord
        (request/reply by digest only; handler is host-injected)
    ZeroMQPatterns.pubsub(publisher_id, topic, payload_digest, seq)
        -> sealed PublishRecord (matched subscribers booked as data)
    ZeroMQPatterns.pipeline(pusher_id, task_digest, seq) -> sealed TaskRecord
        (deterministic round-robin over connected pull workers)
    ZeroMQPatterns.ack(task_id, ok, seq) -> sealed AckRecord

All messaging is deterministic single-host bookkeeping over host-reported
data (GIGO boundary): no sockets are opened, no bytes cross the wire.
Payloads are booked by ``sha256:`` digest only; the module never sees
payload bytes and never proves delivery. The injected ``handler`` and
reported acks are host decisions, recorded as data.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (failed mutations consume their seq), no wall-clock, RLock-guarded,
fail-closed, stdlib-only, ``sha256:`` digest pins, ``audit.ndjson/1`` events.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Tuple


_MODULE_VERSION = "zeromq-patterns.v1"
_SCHEMA_PIN = "northstar.zeromq-patterns.v1"
_AUDIT_TYPE = "audit.ndjson/1"

# Pinned ZeroMQ socket-pattern vocabulary.
PATTERNS = ("req", "rep", "pub", "sub", "push", "pull")

# Pairing rules: (socket pattern) -> tuple of connectable peer patterns.
# pub/sub connect via subscribe(), not connect().
_CONNECT_PEERS = {
    "req": ("rep",),
    "rep": ("req",),
    "push": ("pull",),
    "pull": ("push",),
}

# Maximum topic length (bytes, UTF-8) — mirrors sane broker limits.
_MAX_TOPIC_LEN = 256


class ZeroMQPatternsError(ValueError):
    """Base for all zeromq_patterns errors."""


class BadSocketError(ZeroMQPatternsError):
    """Socket id or pattern failed validation."""


class DuplicateSocketError(ZeroMQPatternsError):
    """A socket with this id is already registered."""


class UnknownSocketError(ZeroMQPatternsError):
    """Socket id not found."""


class BadConnectError(ZeroMQPatternsError):
    """connect() pairing violated the pattern rules."""


class BadSubscriptionError(ZeroMQPatternsError):
    """subscribe() failed validation (non-sub socket, bad topic)."""


class BadExchangeError(ZeroMQPatternsError):
    """reqrep() failed validation."""


class BadPublishError(ZeroMQPatternsError):
    """pubsub() failed validation."""


class BadPipelineError(ZeroMQPatternsError):
    """pipeline() failed validation."""


class BadAckError(ZeroMQPatternsError):
    """ack() failed validation."""


class SeqOrderError(ZeroMQPatternsError):
    """Caller seq did not strictly increase."""


def _reject(reason: str) -> ZeroMQPatternsError:
    table = {
        "bad-socket": BadSocketError,
        "duplicate": DuplicateSocketError,
        "unknown": UnknownSocketError,
        "bad-connect": BadConnectError,
        "bad-subscription": BadSubscriptionError,
        "bad-exchange": BadExchangeError,
        "bad-publish": BadPublishError,
        "bad-pipeline": BadPipelineError,
        "bad-ack": BadAckError,
        "seq": SeqOrderError,
    }
    return table.get(reason, ZeroMQPatternsError)(reason)


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _digest(kind: str, payload: Any) -> str:
    h = hashlib.sha256()
    h.update(kind.encode("utf-8"))
    h.update(b"\x00")
    h.update(_canonical(payload).encode("utf-8"))
    return "sha256:" + h.hexdigest()


def _check_seq_kind(seq: Any) -> None:
    # bool is an int subclass; reject it explicitly (house discipline).
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise _reject("seq")


def _check_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or not value.strip():
        raise ZeroMQPatternsError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_digest(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ZeroMQPatternsError(
            f"{field_name} must be a 'sha256:' digest reference"
        )
    hexpart = value[len("sha256:"):]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise ZeroMQPatternsError(
            f"{field_name} must be 'sha256:' + 64 lowercase hex chars"
        )
    return value


def _check_topic(value: Any) -> str:
    if not isinstance(value, str):
        raise BadSubscriptionError("topic must be a string")
    if len(value.encode("utf-8")) > _MAX_TOPIC_LEN:
        raise BadSubscriptionError("topic too long")
    return value


# ---------------------------------------------------------------------------
# Sealed records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SocketRecord:
    socket_id: str
    pattern: str
    created_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("socket", payload)


@dataclass(frozen=True)
class ConnectionRecord:
    connection_id: str
    socket_id: str
    peer_id: str
    connected_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("connection", payload)


@dataclass(frozen=True)
class SubscriptionRecord:
    subscription_id: str
    socket_id: str
    topic: str
    subscribed_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("subscription", payload)


@dataclass(frozen=True)
class ExchangeRecord:
    exchange_id: str
    client_id: str
    server_id: str
    request_digest: str
    reply_digest: str
    exchanged_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("exchange", payload)


@dataclass(frozen=True)
class PublishRecord:
    publish_id: str
    publisher_id: str
    topic: str
    payload_digest: str
    matched_subscribers: Tuple[str, ...]
    published_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("publish", payload)


@dataclass(frozen=True)
class TaskRecord:
    task_id: str
    pusher_id: str
    worker_id: str
    task_digest: str
    pushed_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("task", payload)


@dataclass(frozen=True)
class AckRecord:
    ack_id: str
    task_id: str
    worker_id: str
    ok: bool
    acked_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("ack", payload)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


def _default_handler(server_id: str, request_digest: str) -> str:
    """Deterministic in-process responder: reply digest derived from input."""
    return _digest("default-reply", {"server": server_id, "req": request_digest})


class ZeroMQPatterns:
    """Deterministic ZeroMQ-pattern messaging bookkeeping.

    Args:
        audit: caller-supplied ``(event_dict) -> None`` sink for
            ``audit.ndjson/1`` events. Must be callable.
    """

    def __init__(self, audit: Callable[[Dict[str, Any]], None]) -> None:
        if not callable(audit):
            raise ZeroMQPatternsError("audit must be callable")
        self._audit = audit
        self._lock = threading.RLock()
        self._seq = 0
        self._socket_counter = 0
        self._connection_counter = 0
        self._subscription_counter = 0
        self._exchange_counter = 0
        self._publish_counter = 0
        self._task_counter = 0
        self._ack_counter = 0
        self._sockets: Dict[str, SocketRecord] = {}
        self._connections: Dict[str, ConnectionRecord] = {}
        # socket_id -> peer ids (undirected view, stored per endpoint)
        self._peers: Dict[str, List[str]] = {}
        # socket_id -> [SubscriptionRecord]
        self._subscriptions: Dict[str, List[SubscriptionRecord]] = {}
        self._exchanges: Dict[str, ExchangeRecord] = {}
        self._publishes: Dict[str, PublishRecord] = {}
        self._tasks: Dict[str, TaskRecord] = {}
        self._acks: Dict[str, AckRecord] = {}
        self._acked_tasks: set = set()
        # push socket id -> round-robin cursor for pipeline dispatch
        self._rr_cursor: Dict[str, int] = {}

    # -- internal helpers ----------------------------------------------------

    def _require_seq(self, seq: int) -> None:
        _check_seq_kind(seq)
        if seq <= self._seq:
            raise _reject("seq")
        self._seq = seq

    def _emit(self, kind: str, seq: int, detail: Dict[str, Any]) -> None:
        self._audit(
            {
                "schema_version": _AUDIT_TYPE,
                "component": "northstar-agent-runtime",
                "module": _MODULE_VERSION,
                "event": kind,
                "seq": seq,
                "detail": detail,
            }
        )

    def _reject_locked(self, seq: int, reason: str) -> ZeroMQPatternsError:
        # Failed mutations consume their seq (house discipline) and are
        # booked as rejected audit rows.
        self._require_seq(seq)
        self._emit("rejected", seq, {"reason": reason})
        return _reject(reason)

    def _seal(self, kind: str, record: Any) -> Any:
        payload = {k: v for k, v in asdict(record).items() if k != "digest"}
        digest = _digest(kind, payload)
        return record.__class__(**{**payload, "digest": digest})

    # -- sockets ---------------------------------------------------------------

    def socket(self, socket_id: str, pattern: str, seq: int) -> SocketRecord:
        """Register a socket with a pinned ZeroMQ pattern."""
        with self._lock:
            if pattern not in PATTERNS:
                raise self._reject_locked(seq, "bad-socket")
            try:
                socket_id = _check_id(socket_id, "socket_id")
            except ZeroMQPatternsError:
                raise self._reject_locked(seq, "bad-socket")
            if socket_id in self._sockets:
                raise self._reject_locked(seq, "duplicate")
            self._require_seq(seq)
            self._socket_counter += 1
            rec = self._seal(
                "socket",
                SocketRecord(
                    socket_id=socket_id,
                    pattern=pattern,
                    created_at_seq=seq,
                ),
            )
            self._sockets[socket_id] = rec
            self._peers[socket_id] = []
            self._emit(
                "socket-created",
                seq,
                {"socket_id": socket_id, "pattern": pattern,
                 "digest": rec.digest},
            )
            return rec

    def connect(self, socket_id: str, peer_id: str, seq: int) -> ConnectionRecord:
        """Pair two sockets (req<->rep, push<->pull only)."""
        with self._lock:
            if socket_id not in self._sockets:
                raise self._reject_locked(seq, "unknown")
            if peer_id not in self._sockets:
                raise self._reject_locked(seq, "unknown")
            if socket_id == peer_id:
                raise self._reject_locked(seq, "bad-connect")
            mine = self._sockets[socket_id].pattern
            peer = self._sockets[peer_id].pattern
            if peer not in _CONNECT_PEERS.get(mine, ()):
                raise self._reject_locked(seq, "bad-connect")
            self._require_seq(seq)
            self._connection_counter += 1
            cid = f"conn-{self._connection_counter}"
            rec = self._seal(
                "connection",
                ConnectionRecord(
                    connection_id=cid,
                    socket_id=socket_id,
                    peer_id=peer_id,
                    connected_at_seq=seq,
                ),
            )
            self._connections[cid] = rec
            self._peers[socket_id].append(peer_id)
            self._peers[peer_id].append(socket_id)
            self._emit(
                "connected",
                seq,
                {"connection_id": cid, "socket_id": socket_id,
                 "peer_id": peer_id, "digest": rec.digest},
            )
            return rec

    def subscribe(self, socket_id: str, topic: str, seq: int) -> SubscriptionRecord:
        """Attach a topic filter to a sub socket (ZeroMQ prefix matching)."""
        with self._lock:
            if socket_id not in self._sockets:
                raise self._reject_locked(seq, "unknown")
            if self._sockets[socket_id].pattern != "sub":
                raise self._reject_locked(seq, "bad-subscription")
            try:
                topic = _check_topic(topic)
            except BadSubscriptionError:
                raise self._reject_locked(seq, "bad-subscription")
            self._require_seq(seq)
            self._subscription_counter += 1
            sid = f"sub-{self._subscription_counter}"
            rec = self._seal(
                "subscription",
                SubscriptionRecord(
                    subscription_id=sid,
                    socket_id=socket_id,
                    topic=topic,
                    subscribed_at_seq=seq,
                ),
            )
            self._subscriptions.setdefault(socket_id, []).append(rec)
            self._emit(
                "subscribed",
                seq,
                {"subscription_id": sid, "socket_id": socket_id,
                 "digest": rec.digest},
            )
            return rec

    # -- patterns ----------------------------------------------------------------

    def reqrep(
        self,
        client_id: str,
        server_id: str,
        request_digest: str,
        seq: int,
        handler: Optional[Callable[[str, str], str]] = None,
    ) -> ExchangeRecord:
        """Book one request/reply exchange; the reply is host-handled.

        ``request_digest`` is a ``sha256:`` reference; the module never
        sees payload bytes. The reply digest comes from the host-injected
        ``handler(server_id, request_digest)`` (default: deterministic
        in-process derivation). The exchange outcome is data, never a
        delivery proof.
        """
        with self._lock:
            bad = None
            if client_id not in self._sockets:
                bad = "unknown"
            elif server_id not in self._sockets:
                bad = "unknown"
            else:
                cpat = self._sockets[client_id].pattern
                spat = self._sockets[server_id].pattern
                if not (
                    (cpat == "req" and spat == "rep")
                    or (cpat == "rep" and spat == "req")
                ):
                    bad = "bad-exchange"
            try:
                _check_digest(request_digest, "request_digest")
            except ZeroMQPatternsError:
                bad = "bad-exchange"
            if bad is not None:
                raise self._reject_locked(seq, bad)
            if handler is None:
                handler = _default_handler
            if not callable(handler):
                raise self._reject_locked(seq, "bad-exchange")
            self._require_seq(seq)
            try:
                reply = handler(server_id, request_digest)
            except Exception:
                # A raising handler is fail-closed: booked as rejected.
                self._emit(
                    "rejected",
                    seq,
                    {"reason": "bad-exchange", "stage": "handler-raised"},
                )
                raise BadExchangeError("handler raised")
            try:
                reply_digest = _check_digest(reply, "reply_digest")
            except ZeroMQPatternsError:
                self._emit(
                    "rejected",
                    seq,
                    {"reason": "bad-exchange", "stage": "bad-reply-digest"},
                )
                raise BadExchangeError("handler returned bad reply digest")
            self._exchange_counter += 1
            xid = f"x-{self._exchange_counter}"
            rec = self._seal(
                "exchange",
                ExchangeRecord(
                    exchange_id=xid,
                    client_id=client_id,
                    server_id=server_id,
                    request_digest=request_digest,
                    reply_digest=reply_digest,
                    exchanged_at_seq=seq,
                ),
            )
            self._exchanges[xid] = rec
            self._emit(
                "requested",
                seq,
                {"exchange_id": xid, "client_id": client_id,
                 "server_id": server_id, "reply_digest": reply_digest,
                 "digest": rec.digest},
            )
            return rec

    def pubsub(
        self,
        publisher_id: str,
        topic: str,
        payload_digest: str,
        seq: int,
    ) -> PublishRecord:
        """Book one publish; matched subscribers are recorded as data.

        ZeroMQ prefix matching: a subscription with topic ``T`` matches a
        publish with topic ``P`` iff ``P.startswith(T)`` (empty topic
        matches everything). Matching is computed over registered
        subscriptions only — no bytes are delivered anywhere.
        """
        with self._lock:
            bad = None
            if publisher_id not in self._sockets:
                bad = "unknown"
            elif self._sockets[publisher_id].pattern != "pub":
                bad = "bad-publish"
            try:
                topic = _check_topic(topic)
            except BadSubscriptionError:
                bad = "bad-publish"
            try:
                _check_digest(payload_digest, "payload_digest")
            except ZeroMQPatternsError:
                bad = "bad-publish"
            if bad is not None:
                raise self._reject_locked(seq, bad)
            self._require_seq(seq)
            matched: List[str] = []
            for sid, subs in self._subscriptions.items():
                for s in subs:
                    if topic.startswith(s.topic):
                        matched.append(sid)
                        break
            matched.sort()
            self._publish_counter += 1
            pid = f"pub-{self._publish_counter}"
            rec = self._seal(
                "publish",
                PublishRecord(
                    publish_id=pid,
                    publisher_id=publisher_id,
                    topic=topic,
                    payload_digest=payload_digest,
                    matched_subscribers=tuple(matched),
                    published_at_seq=seq,
                ),
            )
            self._publishes[pid] = rec
            self._emit(
                "published",
                seq,
                {"publish_id": pid, "publisher_id": publisher_id,
                 "matched": len(matched), "digest": rec.digest},
            )
            return rec

    def pipeline(
        self,
        pusher_id: str,
        task_digest: str,
        seq: int,
    ) -> TaskRecord:
        """Book one pushed task; routed round-robin over pull peers.

        Deterministic single-host round-robin over the pusher's connected
        ``pull`` peers. With no connected pull peer the call refuses
        fail-closed instead of dropping the task silently.
        """
        with self._lock:
            bad = None
            if pusher_id not in self._sockets:
                bad = "unknown"
            elif self._sockets[pusher_id].pattern != "push":
                bad = "bad-pipeline"
            try:
                _check_digest(task_digest, "task_digest")
            except ZeroMQPatternsError:
                bad = "bad-pipeline"
            if bad is not None:
                raise self._reject_locked(seq, bad)
            workers = [
                p for p in self._peers.get(pusher_id, [])
                if self._sockets[p].pattern == "pull"
            ]
            workers.sort()
            if not workers:
                raise self._reject_locked(seq, "bad-pipeline")
            self._require_seq(seq)
            cursor = self._rr_cursor.get(pusher_id, 0)
            worker_id = workers[cursor % len(workers)]
            self._rr_cursor[pusher_id] = cursor + 1
            self._task_counter += 1
            tid = f"task-{self._task_counter}"
            rec = self._seal(
                "task",
                TaskRecord(
                    task_id=tid,
                    pusher_id=pusher_id,
                    worker_id=worker_id,
                    task_digest=task_digest,
                    pushed_at_seq=seq,
                ),
            )
            self._tasks[tid] = rec
            self._emit(
                "task-pushed",
                seq,
                {"task_id": tid, "pusher_id": pusher_id,
                 "worker_id": worker_id, "digest": rec.digest},
            )
            return rec

    def ack(self, task_id: str, ok: bool, seq: int) -> AckRecord:
        """Book the host-reported completion of a task (verdicts are data)."""
        with self._lock:
            if task_id not in self._tasks:
                raise self._reject_locked(seq, "unknown")
            if not isinstance(ok, bool):
                raise self._reject_locked(seq, "bad-ack")
            if task_id in self._acked_tasks:
                raise self._reject_locked(seq, "bad-ack")
            self._require_seq(seq)
            self._ack_counter += 1
            aid = f"ack-{self._ack_counter}"
            rec = self._seal(
                "ack",
                AckRecord(
                    ack_id=aid,
                    task_id=task_id,
                    worker_id=self._tasks[task_id].worker_id,
                    ok=ok,
                    acked_at_seq=seq,
                ),
            )
            self._acks[aid] = rec
            self._acked_tasks.add(task_id)
            self._emit(
                "task-acked",
                seq,
                {"ack_id": aid, "task_id": task_id, "ok": ok,
                 "digest": rec.digest},
            )
            return rec

    # -- read views -------------------------------------------------------------

    def socket_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._sockets))

    def pattern_of(self, socket_id: str) -> str:
        with self._lock:
            if socket_id not in self._sockets:
                raise UnknownSocketError(socket_id)
            return self._sockets[socket_id].pattern

    def peers_of(self, socket_id: str) -> Tuple[str, ...]:
        with self._lock:
            if socket_id not in self._sockets:
                raise UnknownSocketError(socket_id)
            return tuple(sorted(self._peers[socket_id]))

    def subscriptions_of(self, socket_id: str) -> Tuple[SubscriptionRecord, ...]:
        with self._lock:
            if socket_id not in self._sockets:
                raise UnknownSocketError(socket_id)
            return tuple(self._subscriptions.get(socket_id, []))

    def exchange(self, exchange_id: str) -> ExchangeRecord:
        with self._lock:
            if exchange_id not in self._exchanges:
                raise ZeroMQPatternsError(f"unknown exchange: {exchange_id!r}")
            return self._exchanges[exchange_id]

    def task(self, task_id: str) -> TaskRecord:
        with self._lock:
            if task_id not in self._tasks:
                raise ZeroMQPatternsError(f"unknown task: {task_id!r}")
            return self._tasks[task_id]

    def is_acked(self, task_id: str) -> bool:
        with self._lock:
            return task_id in self._acked_tasks

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "sockets": len(self._sockets),
                "connections": len(self._connections),
                "subscriptions": sum(len(v) for v in self._subscriptions.values()),
                "exchanges": len(self._exchanges),
                "publishes": len(self._publishes),
                "tasks": len(self._tasks),
                "acks": len(self._acks),
            }


# ---------------------------------------------------------------------------
# Module-level audit-event helper
# ---------------------------------------------------------------------------


def zeromq_patterns_audit_event(
    kind: str, seq: int, detail: Dict[str, Any]
) -> Dict[str, Any]:
    allowed = {
        "socket-created", "connected", "subscribed", "requested", "replied",
        "published", "task-pushed", "task-acked", "rejected",
    }
    if kind not in allowed:
        raise ZeroMQPatternsError(f"unknown audit kind: {kind!r}")
    return {
        "schema_version": _AUDIT_TYPE,
        "component": "northstar-agent-runtime",
        "module": _MODULE_VERSION,
        "event": kind,
        "seq": seq,
        "detail": detail,
    }


def _stdlib_only_ok(path: str) -> Tuple[bool, str]:
    import ast

    allowed = {
        "hashlib", "json", "threading", "dataclasses", "typing",
        "__future__", "ast",
    }
    with open(path, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False, f"import {a.name}"
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False, f"from {node.module} import"
    return True, ""


def main() -> int:
    events: List[Dict[str, Any]] = []
    zp = ZeroMQPatterns(audit=events.append)

    # req/rep
    c = zp.socket("cli", "req", 1)
    assert c.verify_digest()
    s = zp.socket("srv", "rep", 2)
    assert s.verify_digest()
    zp.connect("cli", "srv", 3)
    req = _digest("req", {"q": 1})
    x = zp.reqrep("cli", "srv", req, 4)
    assert x.verify_digest() and x.request_digest == req
    assert x.reply_digest == _default_handler("srv", req)

    # pub/sub with prefix matching
    p = zp.socket("pub1", "pub", 5)
    assert p.verify_digest()
    sub1 = zp.socket("sub1", "sub", 6)
    assert sub1.verify_digest()
    zp.subscribe("sub1", "news.", 7)
    payload = _digest("payload", {"n": 1})
    pub = zp.pubsub("pub1", "news.sports", payload, 8)
    assert pub.verify_digest() and pub.matched_subscribers == ("sub1",)
    pub2 = zp.pubsub("pub1", "weather", payload, 9)
    assert pub2.matched_subscribers == ()

    # pipeline round-robin
    v = zp.socket("vent", "push", 10)
    assert v.verify_digest()
    w1 = zp.socket("w1", "pull", 11)
    assert w1.verify_digest()
    w2 = zp.socket("w2", "pull", 12)
    assert w2.verify_digest()
    zp.connect("vent", "w1", 13)
    zp.connect("vent", "w2", 14)
    t1 = zp.pipeline("vent", _digest("task", {"i": 1}), 15)
    t2 = zp.pipeline("vent", _digest("task", {"i": 2}), 16)
    assert t1.worker_id == "w1" and t2.worker_id == "w2"
    a = zp.ack(t1.task_id, True, 17)
    assert a.verify_digest() and zp.is_acked(t1.task_id)

    print("zeromq-patterns OK: socket, connect, subscribe, reqrep, pubsub, pipeline, ack")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
