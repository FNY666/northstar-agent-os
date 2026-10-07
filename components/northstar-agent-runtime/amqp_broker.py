"""AMQPBroker: RabbitMQ-shaped exchange/queue/bind message routing.

Research note: AMQP 0-9-1 (RabbitMQ) routes messages through *exchanges* to
*queues* via *bindings*. The exchange *kind* decides how a message's
routing key selects queues:

* **direct** — exact match: a queue bound with key ``k`` receives messages
  published with routing key ``k`` (empty matches empty).
* **fanout** — broadcast: every queue bound to the exchange receives every
  message; routing keys are ignored.
* **topic** — pattern match over dot-separated words: ``*`` matches exactly
  one word, ``#`` matches zero or more words (``logs.#`` matches ``logs``
  and ``logs.a.b``; ``*.error`` matches ``db.error`` but not ``db``).
* **headers** — match on message headers instead of the routing key: a
  binding declares required header pairs plus ``x-match`` (``all``/``any``);
  the routing key is ignored.

Queuing is a *routing* ledger, not a consumer: ``publish()`` books one
frozen :class:`RoutedMessage` per selected queue in deterministic order
(exchange id, queue id). There is no transport, no consumer ack, no
persistence beyond the calling process, and no delivery guarantee beyond
the ledger itself. Payloads are pinned by digest — bytes never enter
records or the audit boundary.

Fail-closed rules: declaring a duplicate exchange/queue, binding to an
unknown exchange/queue, double-binding the same (exchange, queue,
binding key), publishing to an unknown exchange, a binding key that is
malformed for the exchange kind, or a non-increasing caller seq all raise.
Failed mutations consume their seq (batch-21 discipline) and book a
``rejected`` audit row.

Honest scope: this books *declared* topology and *reported* publishes. It
cannot prove a consumer received anything, cannot observe a wire, and the
host-supplied payload digest is GIGO — the module pins what the caller
hands it.

Version pin: amqp-broker.v1
Schema pin: northstar.amqp-broker.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Tuple

#: Module version.
AMQP_BROKER_VERSION = "amqp-broker.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.amqp-broker.v1"

#: Pinned exchange kinds (AMQP 0-9-1 §3.1.3).
EXCHANGE_KINDS = ("direct", "fanout", "topic", "headers")


class AMQPBrokerError(Exception):
    """Base error for AMQP broker misuse."""


class BadExchangeError(AMQPBrokerError):
    """An exchange id or kind is malformed."""


class DuplicateExchangeError(AMQPBrokerError):
    """An exchange id is already declared."""


class UnknownExchangeError(AMQPBrokerError):
    """Operation names an exchange the broker does not know."""


class BadQueueError(AMQPBrokerError):
    """A queue id is malformed."""


class DuplicateQueueError(AMQPBrokerError):
    """A queue id is already declared."""


class UnknownQueueError(AMQPBrokerError):
    """Operation names a queue the broker does not know."""


class BadBindingError(AMQPBrokerError):
    """A binding key or headers spec is malformed for the exchange kind."""


class DuplicateBindingError(AMQPBrokerError):
    """The identical binding already exists."""


class SeqOrderError(AMQPBrokerError):
    """Caller seq did not strictly increase."""


class PayloadError(AMQPBrokerError):
    """A payload cannot be pinned."""


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AMQPBrokerError(f"{what} must be a non-empty str")
    return value.strip()


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_routing_key(value: Any, what: str = "routing key") -> str:
    """Routing keys may be empty but must be a clean dot-word string."""
    if not isinstance(value, str):
        raise AMQPBrokerError(f"{what} must be a str")
    if value == "":
        return ""
    words = value.split(".")
    for word in words:
        if not word:
            raise BadBindingError(f"{what} has an empty word: {value!r}")
        if word in ("*", "#"):
            raise BadBindingError(f"{what} must not contain wildcards: {value!r}")
    return value


def _check_topic_binding_key(value: Any) -> str:
    """Validate an AMQP topic binding key (``*``/``#`` wildcards allowed)."""
    if not isinstance(value, str) or not value:
        raise BadBindingError("topic binding key must be a non-empty str")
    words = value.split(".")
    for word in words:
        if not word:
            raise BadBindingError(f"topic binding key has an empty word: {value!r}")
        if word not in ("*", "#") and ("*" in word or "#" in word):
            raise BadBindingError(
                f"wildcards must occupy a whole word: {value!r}"
            )
    return value


def _topic_matches(binding_key: str, routing_key: str) -> bool:
    """AMQP topic match: ``*`` = one word, ``#`` = zero or more words."""
    b_words = binding_key.split(".")
    r_words = routing_key.split(".") if routing_key else []

    def rec(bi: int, ri: int) -> bool:
        if bi == len(b_words):
            return ri == len(r_words)
        if b_words[bi] == "#":
            # '#' matches zero or more words.
            return any(rec(bi + 1, rj) for rj in range(ri, len(r_words) + 1))
        if ri == len(r_words):
            return False
        if b_words[bi] == "*" or b_words[bi] == r_words[ri]:
            return rec(bi + 1, ri + 1)
        return False

    return rec(0, 0)


def _check_headers_spec(value: Any) -> Mapping[str, str]:
    """Validate a headers-exchange binding spec.

    A mapping of required header matches; ``x-match`` (default ``all``)
    selects whether every pair or any pair must match.
    """
    if value is None:
        return {"x-match": "all"}
    if not isinstance(value, Mapping):
        raise BadBindingError("headers spec must be a mapping")
    spec: dict[str, str] = {}
    for key, val in value.items():
        if not isinstance(key, str) or not key:
            raise BadBindingError("header names must be non-empty str")
        if key == "x-match":
            if val not in ("all", "any"):
                raise BadBindingError("x-match must be 'all' or 'any'")
        else:
            if not isinstance(val, str):
                raise BadBindingError("header values must be str")
        spec[key] = val
    spec.setdefault("x-match", "all")
    return spec


def _headers_match(spec: Mapping[str, str], message: Mapping[str, str]) -> bool:
    mode = spec.get("x-match", "all")
    pairs = [(k, v) for k, v in spec.items() if k != "x-match"]
    if not pairs:
        return True
    results = [message.get(k) == v for k, v in pairs]
    return all(results) if mode == "all" else any(results)


def _canonical(value: Any) -> bytes:
    """Type-tagged canonical encoding for payload pinning."""
    if isinstance(value, bool):
        return b"b:" + (b"1" if value else b"0")
    if isinstance(value, int):
        return b"i:" + str(value).encode("ascii")
    if isinstance(value, float):
        import math

        if math.isnan(value) or math.isinf(value):
            raise PayloadError("NaN/inf payloads cannot be pinned")
        if value == int(value) and abs(value) >= 2**53:
            raise PayloadError("integral float beyond 2**53 cannot be pinned safely")
        return b"f:" + repr(value).encode("ascii")
    if isinstance(value, str):
        return b"s:" + value.encode("utf-8")
    if value is None:
        return b"n:"
    if isinstance(value, bytes):
        return b"y:" + value.hex().encode("ascii")
    if isinstance(value, (list, tuple)):
        return b"l:" + b",".join(_canonical(v) for v in value)
    if isinstance(value, Mapping):
        for k in value:
            if not isinstance(k, str):
                raise PayloadError("mapping keys must be str")
        return b"m:" + b",".join(
            _canonical(k) + b"=" + _canonical(value[k]) for k in sorted(value)
        )
    raise PayloadError(f"payload of type {type(value).__name__} cannot be pinned")


def _pin(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return "sha256:" + digest.hexdigest()


@dataclass(frozen=True)
class ExchangeRecord:
    """One declared exchange."""

    exchange_id: str
    kind: str
    seq: int
    digest: str
    version: str = AMQP_BROKER_VERSION
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class QueueRecord:
    """One declared queue."""

    queue_id: str
    seq: int
    digest: str
    version: str = AMQP_BROKER_VERSION
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class BindingRecord:
    """One exchange -> queue binding."""

    exchange_id: str
    queue_id: str
    binding_key: str
    headers_spec: Tuple[Tuple[str, str], ...] = field(compare=False)
    seq: int = 0
    digest: str = ""
    version: str = AMQP_BROKER_VERSION
    schema: str = SCHEMA_PIN

    def headers(self) -> Mapping[str, str]:
        return dict(self.headers_spec)


@dataclass(frozen=True)
class RoutedMessage:
    """One message routed to one queue (payload pinned, never stored)."""

    exchange_id: str
    queue_id: str
    routing_key: str
    payload_digest: str
    seq: int
    digest: str
    version: str = AMQP_BROKER_VERSION
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class PublishReport:
    """Outcome of one publish call: routed messages + digest pin."""

    exchange_id: str
    routing_key: str
    seq: int
    routed: Tuple[RoutedMessage, ...]
    digest: str
    version: str = AMQP_BROKER_VERSION
    schema: str = SCHEMA_PIN

    @property
    def routed_count(self) -> int:
        return len(self.routed)


class AMQPBroker:
    """In-memory AMQP 0-9-1 exchange/queue/bind routing ledger.

    Exchanges and queues are declared by id; ``bind()`` wires a queue to
    an exchange with a binding key (or headers spec for ``headers``
    exchanges); ``publish()`` routes per the exchange kind and returns a
    frozen :class:`PublishReport`. All mutation seqs are caller-supplied
    and must strictly increase; failed mutations consume their seq.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._exchanges: dict[str, ExchangeRecord] = {}
        self._queues: dict[str, QueueRecord] = {}
        self._bindings: list[BindingRecord] = []
        self._last_seq = -1
        self._published = 0
        self._rejected = 0
        self._audit: list[Mapping[str, Any]] = []

    # -- seq + audit plumbing -------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **fields: Any) -> None:
        self._audit.append(
            {
                "kind": f"amqp-broker.{kind}",
                "seq": seq,
                "version": AMQP_BROKER_VERSION,
                "schema": SCHEMA_PIN,
                **fields,
            }
        )

    def _reject(self, seq: int, reason: str) -> None:
        self._rejected += 1
        self._emit("rejected", seq, reason=reason)

    # -- declarations ----------------------------------------------------

    def exchange(self, exchange_id: str, kind: str, seq: int) -> ExchangeRecord:
        """Declare an exchange of one pinned kind."""
        exchange_id = _check_id(exchange_id, "exchange_id")
        if kind not in EXCHANGE_KINDS:
            self._reject(seq if isinstance(seq, int) and not isinstance(seq, bool) else 0,
                         f"unknown exchange kind {kind!r}")
            raise BadExchangeError(f"unknown exchange kind {kind!r}")
        with self._lock:
            seq = self._next_seq(seq)
            if exchange_id in self._exchanges:
                self._reject(seq, f"duplicate exchange {exchange_id!r}")
                raise DuplicateExchangeError(f"exchange {exchange_id!r} already declared")
            record = ExchangeRecord(
                exchange_id=exchange_id,
                kind=kind,
                seq=seq,
                digest=_pin(
                    b"exchange",
                    exchange_id.encode("utf-8"),
                    kind.encode("utf-8"),
                    seq.to_bytes(8, "big"),
                ),
            )
            self._exchanges[exchange_id] = record
            self._emit("exchange-declared", seq,
                       exchange_id=exchange_id, exchange_kind=kind, digest=record.digest)
            return record

    def queue(self, queue_id: str, seq: int) -> QueueRecord:
        """Declare a queue."""
        queue_id = _check_id(queue_id, "queue_id")
        with self._lock:
            seq = self._next_seq(seq)
            if queue_id in self._queues:
                self._reject(seq, f"duplicate queue {queue_id!r}")
                raise DuplicateQueueError(f"queue {queue_id!r} already declared")
            record = QueueRecord(
                queue_id=queue_id,
                seq=seq,
                digest=_pin(b"queue", queue_id.encode("utf-8"), seq.to_bytes(8, "big")),
            )
            self._queues[queue_id] = record
            self._emit("queue-declared", seq,
                       queue_id=queue_id, digest=record.digest)
            return record

    def bind(
        self,
        exchange_id: str,
        queue_id: str,
        binding_key: str = "",
        seq: int = 0,
        headers: Mapping[str, str] | None = None,
    ) -> BindingRecord:
        """Bind ``queue_id`` to ``exchange_id``.

        ``binding_key`` semantics follow the exchange kind (exact for
        ``direct``, ignored for ``fanout``, topic pattern for ``topic``,
        must be empty for ``headers`` — pass ``headers=`` there instead).
        """
        exchange_id = _check_id(exchange_id, "exchange_id")
        queue_id = _check_id(queue_id, "queue_id")
        with self._lock:
            seq = self._next_seq(seq)
            exchange = self._exchanges.get(exchange_id)
            if exchange is None:
                self._reject(seq, f"unknown exchange {exchange_id!r}")
                raise UnknownExchangeError(f"unknown exchange {exchange_id!r}")
            if queue_id not in self._queues:
                self._reject(seq, f"unknown queue {queue_id!r}")
                raise UnknownQueueError(f"unknown queue {queue_id!r}")

            headers_spec: Tuple[Tuple[str, str], ...] = ()
            if exchange.kind == "headers":
                if binding_key != "":
                    self._reject(seq, "headers exchange takes headers=, not a binding key")
                    raise BadBindingError("headers exchange takes headers=, not a binding key")
                spec = _check_headers_spec(headers)
                headers_spec = tuple(sorted(spec.items()))
                binding_key = ""
            elif exchange.kind == "topic":
                binding_key = _check_topic_binding_key(binding_key)
            elif exchange.kind == "direct":
                binding_key = _check_routing_key(binding_key, "binding key")
            else:  # fanout: key ignored
                if not isinstance(binding_key, str):
                    raise BadBindingError("binding key must be a str")

            for existing in self._bindings:
                if (
                    existing.exchange_id == exchange_id
                    and existing.queue_id == queue_id
                    and existing.binding_key == binding_key
                    and existing.headers_spec == headers_spec
                ):
                    self._reject(seq, "duplicate binding")
                    raise DuplicateBindingError("identical binding already exists")

            record = BindingRecord(
                exchange_id=exchange_id,
                queue_id=queue_id,
                binding_key=binding_key,
                headers_spec=headers_spec,
                seq=seq,
                digest=_pin(
                    b"bind",
                    exchange_id.encode("utf-8"),
                    queue_id.encode("utf-8"),
                    binding_key.encode("utf-8"),
                    repr(headers_spec).encode("utf-8"),
                    seq.to_bytes(8, "big"),
                ),
            )
            self._bindings.append(record)
            self._emit(
                "bound", seq,
                exchange_id=exchange_id, queue_id=queue_id,
                binding_key=binding_key, digest=record.digest,
            )
            return record

    # -- publish ----------------------------------------------------------

    def publish(
        self,
        exchange_id: str,
        routing_key: str,
        payload: Any,
        seq: int,
        headers: Mapping[str, str] | None = None,
    ) -> PublishReport:
        """Route ``payload`` through ``exchange_id`` to bound queues.

        Returns a frozen :class:`PublishReport`. Publishing to an
        exchange with no matching bindings is a valid no-op (zero
        routed). Payload is pinned by digest; bytes never enter records
        or audit.
        """
        exchange_id = _check_id(exchange_id, "exchange_id")
        routing_key = _check_routing_key(routing_key)
        payload_bytes = _canonical(payload)
        payload_digest = _pin(b"payload", payload_bytes)
        if headers is not None:
            if not isinstance(headers, Mapping):
                raise AMQPBrokerError("headers must be a mapping")
            for k, v in headers.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise AMQPBrokerError("header names and values must be str")
            message_headers = dict(headers)
        else:
            message_headers = {}
        with self._lock:
            seq = self._next_seq(seq)
            exchange = self._exchanges.get(exchange_id)
            if exchange is None:
                self._reject(seq, f"unknown exchange {exchange_id!r}")
                raise UnknownExchangeError(f"unknown exchange {exchange_id!r}")

            matched: list[str] = []
            for binding in self._bindings:
                if binding.exchange_id != exchange_id:
                    continue
                if exchange.kind == "fanout":
                    matched.append(binding.queue_id)
                elif exchange.kind == "direct":
                    if binding.binding_key == routing_key:
                        matched.append(binding.queue_id)
                elif exchange.kind == "topic":
                    if _topic_matches(binding.binding_key, routing_key):
                        matched.append(binding.queue_id)
                else:  # headers
                    if _headers_match(dict(binding.headers_spec), message_headers):
                        matched.append(binding.queue_id)

            routed: list[RoutedMessage] = []
            for queue_id in sorted(set(matched)):
                routed.append(
                    RoutedMessage(
                        exchange_id=exchange_id,
                        queue_id=queue_id,
                        routing_key=routing_key,
                        payload_digest=payload_digest,
                        seq=seq,
                        digest=_pin(
                            b"routed",
                            exchange_id.encode("utf-8"),
                            queue_id.encode("utf-8"),
                            routing_key.encode("utf-8"),
                            payload_digest.encode("ascii"),
                            seq.to_bytes(8, "big"),
                        ),
                    )
                )
            self._published += 1
            report = PublishReport(
                exchange_id=exchange_id,
                routing_key=routing_key,
                seq=seq,
                routed=tuple(routed),
                digest=_pin(
                    b"publish",
                    exchange_id.encode("utf-8"),
                    routing_key.encode("utf-8"),
                    b"".join(r.digest.encode("ascii") for r in routed),
                    seq.to_bytes(8, "big"),
                ),
            )
            self._emit(
                "published", seq,
                exchange_id=exchange_id, routing_key=routing_key,
                routed_count=len(routed), digest=report.digest,
            )
            return report

    # -- views -------------------------------------------------------------

    def exchange_record(self, exchange_id: str) -> ExchangeRecord:
        _check_id(exchange_id, "exchange_id")
        with self._lock:
            try:
                return self._exchanges[exchange_id]
            except KeyError:
                raise UnknownExchangeError(f"unknown exchange {exchange_id!r}")

    def queue_record(self, queue_id: str) -> QueueRecord:
        _check_id(queue_id, "queue_id")
        with self._lock:
            try:
                return self._queues[queue_id]
            except KeyError:
                raise UnknownQueueError(f"unknown queue {queue_id!r}")

    def exchange_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._exchanges))

    def queue_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._queues))

    def bindings(self, exchange_id: str) -> Tuple[BindingRecord, ...]:
        """Bindings on ``exchange_id`` in declaration order."""
        _check_id(exchange_id, "exchange_id")
        with self._lock:
            if exchange_id not in self._exchanges:
                raise UnknownExchangeError(f"unknown exchange {exchange_id!r}")
            return tuple(b for b in self._bindings if b.exchange_id == exchange_id)

    def stats(self) -> Mapping[str, int]:
        with self._lock:
            return {
                "exchanges": len(self._exchanges),
                "queues": len(self._queues),
                "bindings": len(self._bindings),
                "published": self._published,
                "rejected": self._rejected,
            }

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


_AMQP_AUDIT_KINDS = (
    "exchange-declared",
    "queue-declared",
    "bound",
    "published",
    "rejected",
)


def amqp_broker_audit_event(kind: str, seq: int, **fields: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for a broker event.

    Carries pins and ids only — never raw payloads, headers, or keys.
    """
    if kind not in _AMQP_AUDIT_KINDS:
        raise AMQPBrokerError(f"unknown audit kind {kind!r}")
    _check_seq(seq, "seq")
    return {
        "kind": f"amqp-broker.{kind}",
        "seq": seq,
        "version": AMQP_BROKER_VERSION,
        "schema": SCHEMA_PIN,
        **fields,
    }


def main() -> None:
    broker = AMQPBroker()
    broker.exchange("logs", "topic", 1)
    broker.exchange("events", "fanout", 2)
    broker.queue("disk", 3)
    broker.queue("alerts", 4)
    broker.queue("all", 5)
    broker.bind("logs", "disk", "logs.#", 6)
    broker.bind("logs", "alerts", "*.error", 7)
    broker.bind("events", "all", "", 8)
    report = broker.publish("logs", "logs.error", {"msg": "x"}, 9)
    assert report.routed_count == 2, report.routed_count
    report2 = broker.publish("events", "anything", {"n": 1}, 10)
    assert report2.routed_count == 1, report2.routed_count
    report3 = broker.publish("logs", "logs.db.info", {"n": 2}, 11)
    assert report3.routed_count == 1, report3.routed_count
    print("amqp-broker OK: exchange, queue, bind, topic + fanout routing, publish")


if __name__ == "__main__":
    main()
