"""Webhook dispatcher: signed endpoint callbacks with deterministic retry bookkeeping.

Research note: *webhooks* are the push-callback contract used by Stripe,
GitHub, and Twilio to notify subscriber systems of events. The security
shape is well studied (Stripe's webhook signing docs; GitHub's
``X-Hub-Signature-256``; CWE-353-adjacent missing-verification bugs): the
producer signs the canonical payload with a per-endpoint secret
(HMAC-SHA256), the receiver recomputes the signature with
``hmac.compare_digest`` and rejects anything that does not match. Delivery
is at-least-once with *exponential backoff retries* (Stripe retries for up
to ~3 days; GitHub redelivers on 5xx), because the network is unreliable
and receivers go down.

* **Endpoint registration** — ``register(endpoint_id, url, secret, seq)``
  pins one subscriber: a unique id, an ``https://`` URL, and a secret held
  only in memory (never emitted in records or audit events). Plain
  ``http://`` URLs are refused fail-closed (Stripe live-mode discipline:
  signed callbacks over plaintext leak the payload and let a network
  observer capture replays). URLs carrying userinfo (``user:pass@host``)
  are refused: credentials in URLs leak through logs.
* **Signing** — dispatch computes ``sha256=<hex>`` = HMAC-SHA256(secret,
  canonical(payload)) (GitHub's header shape). The signature travels in
  the frozen :class:`DeliveryRecord`; ``verify_sig(secret, payload,
  signature)`` recomputes with ``hmac.compare_digest``. A malformed or
  mismatching signature returns ``False`` — verifying *untrusted* input
  must not raise; only wrong *types* (a programming error) raise.
* **Dispatch is bookkeeping, not HTTP** — ``dispatch()`` mints a delivery
  record with ``status="scheduled"``; the host performs the real HTTP
  POST and reports the outcome via ``report(delivery_id, ok, seq)``. This
  module owns the *retry ledger*, not the socket.
* **Deterministic retries** — on ``ok=False`` the attempt counter
  increments and a backoff delay is *computed* (``base * 2**(attempt-1)``
  logical seqs, capped), never slept: the host schedules against its own
  clock. Exhausting ``max_attempts`` moves the delivery to ``"dead"``
  (the poison-message terminal state); a terminal delivery refuses
  further reports fail-closed.
* **Pins bind, secrets never leak** — every record carries ``sha256:``
  digest pins over its canonical body (delivery id, endpoint id, event
  type, payload digest, seq). Audit events and ``as_dict()`` carry pins
  and ids only — never the secret, never raw payload content.

Honest scope: this is the *signing and retry ledger* for webhooks, not a
delivery guarantee. It cannot prove an endpoint received anything (the
host reports outcomes; a lying host gets a consistent ledger of lies),
cannot prevent replay of a captured valid signature (pair with a
host-side nonce/timestamp, Stripe-style), and cannot see a delivery made
outside :meth:`report`. ``status == "delivered"`` means "the host said
2xx", never "the world changed".

Version pin: webhook-dispatcher.v1
Schema pin: northstar.webhook-dispatcher.v1
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
WEBHOOK_DISPATCHER_VERSION = "webhook-dispatcher.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.webhook-dispatcher.v1"

#: Signature header prefix (GitHub's ``X-Hub-Signature-256`` shape).
SIGNATURE_PREFIX = "sha256="

#: Backoff base in logical seqs; delay for attempt n is base * 2**(n-1).
BACKOFF_BASE_SEQS = 1

#: Backoff cap in logical seqs.
BACKOFF_MAX_SEQS = 64

#: Default retry budget per delivery.
DEFAULT_MAX_ATTEMPTS = 5

_AUDIT_KINDS = frozenset(
    {
        "endpoint-registered",
        "endpoint-removed",
        "dispatched",
        "delivery-reported",
        "verified",
        "rejected",
    }
)


class WebhookError(Exception):
    """Base error for webhook-dispatcher misuse or constraint violations."""


class DuplicateEndpointError(WebhookError):
    """An endpoint id was registered twice (fail-closed: no silent overwrite)."""


class UnknownEndpointError(WebhookError):
    """Dispatch referenced an endpoint id that was never registered."""


class UnknownDeliveryError(WebhookError):
    """A report referenced a delivery id that was never minted."""


class TerminalDeliveryError(WebhookError):
    """A report targeted a delivery already in a terminal state."""


def _check_str(value: Any, name: str, allow_empty: bool = False) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise WebhookError(f"{name} must be a str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise WebhookError(f"{name} must be non-empty")
    return value


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WebhookError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise WebhookError(f"{name} must be non-negative, got {value}")
    return value


def _check_secret(value: Any) -> bytes:
    if isinstance(value, bool):
        raise WebhookError("secret must be bytes or a non-empty str, got bool")
    if isinstance(value, str):
        if not value:
            raise WebhookError("secret must be non-empty")
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        if not value:
            raise WebhookError("secret must be non-empty")
        return bytes(value)
    raise WebhookError(f"secret must be bytes or str, got {type(value).__name__}")


def _check_url(value: Any) -> str:
    url = _check_str(value, "url")
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise WebhookError(
            f"url scheme must be https, got {parts.scheme!r} "
            "(signed callbacks over plaintext http are refused)"
        )
    if not parts.hostname:
        raise WebhookError("url must have a host")
    if parts.username or parts.password:
        raise WebhookError("url must not embed userinfo credentials")
    return url


def _canonical_payload(payload: Any) -> bytes:
    """Canonical bytes for signing; raises WebhookError when unserializable."""
    try:
        return jcs_canonical_json(payload)
    except Exception as exc:
        raise WebhookError(f"payload is not canonicalizable: {exc}") from exc


def _payload_digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_payload(payload)).hexdigest()


def _record_digest(*parts: str) -> str:
    body = "|".join(parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EndpointRecord:
    """One registered subscriber endpoint (frozen; never carries the secret)."""

    version: str
    endpoint_id: str
    url: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "endpoint_id": self.endpoint_id,
            "url": self.url,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class DeliveryRecord:
    """One scheduled webhook delivery (frozen snapshot at mint time)."""

    version: str
    delivery_id: str
    endpoint_id: str
    event_type: str
    payload_digest: str
    signature: str
    attempt: int
    max_attempts: int
    status: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "delivery_id": self.delivery_id,
            "endpoint_id": self.endpoint_id,
            "event_type": self.event_type,
            "payload_digest": self.payload_digest,
            "signature": self.signature,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "status": self.status,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RetryDecision:
    """Outcome of one :meth:`WebhookDispatcher.report` call (frozen)."""

    version: str
    delivery_id: str
    attempt: int
    status: str
    backoff_seqs: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "delivery_id": self.delivery_id,
            "attempt": self.attempt,
            "status": self.status,
            "backoff_seqs": self.backoff_seqs,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class VerificationReport:
    """Outcome of one signature verification (frozen)."""

    version: str
    valid: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "valid": self.valid,
            "digest": self.digest,
        }


def backoff_seqs(attempt: int) -> int:
    """Deterministic backoff delay in logical seqs for 1-based *attempt*.

    ``base * 2**(attempt-1)`` capped at :data:`BACKOFF_MAX_SEQS`; never
    slept here, only computed, so retry scheduling stays deterministic.
    """
    if isinstance(attempt, bool) or not isinstance(attempt, int):
        raise WebhookError(f"attempt must be an int, got {type(attempt).__name__}")
    if attempt < 1:
        raise WebhookError(f"attempt must be >= 1, got {attempt}")
    return min(BACKOFF_MAX_SEQS, BACKOFF_BASE_SEQS * (2 ** (attempt - 1)))


def compute_signature(secret: bytes, payload: Any) -> str:
    """Return the ``sha256=<hex>`` signature for *payload* under *secret*.

    ``secret`` must be bytes (use ``_check_secret`` to normalize first);
    anything else is a programming error and raises ``TypeError``.
    """
    if isinstance(secret, bool) or not isinstance(secret, (bytes, bytearray)):
        raise TypeError(f"secret must be bytes, got {type(secret).__name__}")
    mac = hmac.new(bytes(secret), _canonical_payload(payload), hashlib.sha256)
    return SIGNATURE_PREFIX + mac.hexdigest()


def verify_sig(secret: Any, payload: Any, signature: Any) -> bool:
    """Verify a webhook signature; ``True`` iff it matches.

    Malformed or mismatching signatures return ``False`` — verifying
    *untrusted* input must not raise. Wrong *types* (a programming
    error) raise ``TypeError``/``WebhookError`` instead.
    """
    secret_bytes = _check_secret(secret)
    if isinstance(signature, bool) or not isinstance(signature, str):
        return False
    if not signature.startswith(SIGNATURE_PREFIX):
        return False
    hexpart = signature[len(SIGNATURE_PREFIX):]
    if len(hexpart) != 64:
        return False
    try:
        int(hexpart, 16)
    except ValueError:
        return False
    expected = compute_signature(secret_bytes, payload)
    return hmac.compare_digest(expected, signature)


class WebhookDispatcher:
    """Signed webhook endpoint registry and deterministic retry ledger.

    The dispatcher owns registration, signature minting, and the retry
    state machine. It never performs network I/O: the host POSTs the
    signed payload and reports outcomes via :meth:`report`.
    """

    #: Terminal delivery states (further reports refused).
    TERMINAL_STATES = frozenset({"delivered", "dead"})

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._secrets: Dict[str, bytes] = {}
        self._endpoints: Dict[str, EndpointRecord] = {}
        self._deliveries: Dict[str, Dict[str, Any]] = {}
        self._counter = 0

    # -- registration ----------------------------------------------------

    def register(self, endpoint_id: str, url: str, secret: Any, seq: int) -> EndpointRecord:
        """Register one subscriber endpoint; returns its frozen record.

        ``secret`` is held in memory only — it never appears in the
        record, in ``as_dict()``, or in audit events.
        """
        endpoint_id = _check_str(endpoint_id, "endpoint_id")
        url = _check_url(url)
        secret_bytes = _check_secret(secret)
        _check_seq(seq)
        with self._lock:
            if endpoint_id in self._endpoints:
                raise DuplicateEndpointError(
                    f"endpoint {endpoint_id!r} is already registered"
                )
            record = EndpointRecord(
                version=WEBHOOK_DISPATCHER_VERSION,
                endpoint_id=endpoint_id,
                url=url,
                digest=_record_digest("endpoint", endpoint_id, url, str(seq)),
            )
            self._secrets[endpoint_id] = secret_bytes
            self._endpoints[endpoint_id] = record
            return record

    def remove(self, endpoint_id: str, seq: int) -> None:
        """Remove an endpoint and forget its secret (fail-closed on unknown)."""
        endpoint_id = _check_str(endpoint_id, "endpoint_id")
        _check_seq(seq)
        with self._lock:
            if endpoint_id not in self._endpoints:
                raise UnknownEndpointError(
                    f"endpoint {endpoint_id!r} is not registered"
                )
            del self._endpoints[endpoint_id]
            del self._secrets[endpoint_id]

    def endpoints(self) -> Tuple[EndpointRecord, ...]:
        """Registered endpoints, sorted by id (deterministic view)."""
        with self._lock:
            return tuple(self._endpoints[k] for k in sorted(self._endpoints))

    # -- dispatch --------------------------------------------------------

    def dispatch(
        self,
        endpoint_id: str,
        event_type: str,
        payload: Any,
        seq: int,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ) -> DeliveryRecord:
        """Mint a signed delivery for a registered endpoint.

        The record carries the ``sha256=<hex>`` signature the host must
        POST; the payload itself is pinned by digest only.
        """
        endpoint_id = _check_str(endpoint_id, "endpoint_id")
        event_type = _check_str(event_type, "event_type")
        _check_seq(seq)
        if (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
            or max_attempts < 1
        ):
            raise WebhookError(
                f"max_attempts must be a positive int, got {max_attempts!r}"
            )
        payload_digest = _payload_digest(payload)
        with self._lock:
            if endpoint_id not in self._endpoints:
                raise UnknownEndpointError(
                    f"endpoint {endpoint_id!r} is not registered"
                )
            self._counter += 1
            delivery_id = f"dlv-{self._counter}"
            signature = compute_signature(self._secrets[endpoint_id], payload)
            record = DeliveryRecord(
                version=WEBHOOK_DISPATCHER_VERSION,
                delivery_id=delivery_id,
                endpoint_id=endpoint_id,
                event_type=event_type,
                payload_digest=payload_digest,
                signature=signature,
                attempt=0,
                max_attempts=max_attempts,
                status="scheduled",
                digest=_record_digest(
                    "delivery", delivery_id, endpoint_id, event_type,
                    payload_digest, str(seq),
                ),
            )
            self._deliveries[delivery_id] = {
                "record": record,
                "attempt": 0,
                "status": "scheduled",
            }
            return record

    # -- outcome reporting / retries -------------------------------------

    def report(self, delivery_id: str, ok: Any, seq: int) -> RetryDecision:
        """Record the host-reported outcome of one delivery attempt.

        ``ok=True`` marks the delivery ``"delivered"`` (terminal).
        ``ok=False`` increments the attempt counter: while attempts remain
        the delivery moves to ``"retrying"`` with a computed
        ``backoff_seqs`` delay; on exhaustion it moves to ``"dead"``
        (terminal). Reports against a terminal delivery raise
        :class:`TerminalDeliveryError`.
        """
        delivery_id = _check_str(delivery_id, "delivery_id")
        if not isinstance(ok, bool):
            raise WebhookError(f"ok must be a bool, got {type(ok).__name__}")
        _check_seq(seq)
        with self._lock:
            state = self._deliveries.get(delivery_id)
            if state is None:
                raise UnknownDeliveryError(
                    f"delivery {delivery_id!r} was never minted"
                )
            if state["status"] in self.TERMINAL_STATES:
                raise TerminalDeliveryError(
                    f"delivery {delivery_id!r} is already {state['status']}"
                )
            record: DeliveryRecord = state["record"]
            if ok:
                state["status"] = "delivered"
                decision = RetryDecision(
                    version=WEBHOOK_DISPATCHER_VERSION,
                    delivery_id=delivery_id,
                    attempt=state["attempt"],
                    status="delivered",
                    backoff_seqs=0,
                    digest=_record_digest(
                        "report", delivery_id, "delivered", str(seq)
                    ),
                )
            else:
                state["attempt"] += 1
                attempt = state["attempt"]
                if attempt >= record.max_attempts:
                    state["status"] = "dead"
                    backoff = 0
                else:
                    state["status"] = "retrying"
                    backoff = backoff_seqs(attempt)
                decision = RetryDecision(
                    version=WEBHOOK_DISPATCHER_VERSION,
                    delivery_id=delivery_id,
                    attempt=attempt,
                    status=state["status"],
                    backoff_seqs=backoff,
                    digest=_record_digest(
                        "report", delivery_id, state["status"],
                        str(attempt), str(seq),
                    ),
                )
            return decision

    def delivery(self, delivery_id: str) -> DeliveryRecord:
        """The minted (immutable) record for one delivery."""
        delivery_id = _check_str(delivery_id, "delivery_id")
        with self._lock:
            state = self._deliveries.get(delivery_id)
            if state is None:
                raise UnknownDeliveryError(
                    f"delivery {delivery_id!r} was never minted"
                )
            return state["record"]

    def delivery_status(self, delivery_id: str) -> str:
        """Live status of one delivery (``scheduled``/``retrying``/``delivered``/``dead``)."""
        delivery_id = _check_str(delivery_id, "delivery_id")
        with self._lock:
            state = self._deliveries.get(delivery_id)
            if state is None:
                raise UnknownDeliveryError(
                    f"delivery {delivery_id!r} was never minted"
                )
            return state["status"]

    def pending(self) -> Tuple[str, ...]:
        """Delivery ids still in flight (``scheduled`` or ``retrying``)."""
        with self._lock:
            return tuple(
                did
                for did, state in self._deliveries.items()
                if state["status"] in ("scheduled", "retrying")
            )

    # -- verification helper ---------------------------------------------

    def verify_delivery(
        self, delivery_id: str, payload: Any, signature: Any
    ) -> VerificationReport:
        """Verify *signature* for *payload* against the endpoint's secret.

        Returns a frozen report; ``valid=False`` on any mismatch. The
        secret is looked up internally and never leaves this object.
        """
        delivery_id = _check_str(delivery_id, "delivery_id")
        with self._lock:
            state = self._deliveries.get(delivery_id)
            if state is None:
                raise UnknownDeliveryError(
                    f"delivery {delivery_id!r} was never minted"
                )
            secret = self._secrets[state["record"].endpoint_id]
        valid = verify_sig(secret, payload, signature)
        return VerificationReport(
            version=WEBHOOK_DISPATCHER_VERSION,
            valid=valid,
            digest=_record_digest("verify", delivery_id, str(valid)),
        )


def webhook_dispatcher_audit_event(
    kind: str,
    seq: int,
    endpoint: Optional[EndpointRecord] = None,
    delivery: Optional[DeliveryRecord] = None,
    decision: Optional[RetryDecision] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a dispatcher step.

    ``kind`` is one of ``endpoint-registered`` / ``endpoint-removed`` /
    ``dispatched`` / ``delivery-reported`` / ``verified`` / ``rejected``.
    Secrets and raw payloads are never emitted — only ids and digest
    pins — so sensitive material cannot leak through the audit trail.
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _check_seq(seq)
    if endpoint is not None and not isinstance(endpoint, EndpointRecord):
        raise TypeError("endpoint must be an EndpointRecord")
    if delivery is not None and not isinstance(delivery, DeliveryRecord):
        raise TypeError("delivery must be a DeliveryRecord")
    if decision is not None and not isinstance(decision, RetryDecision):
        raise TypeError("decision must be a RetryDecision")
    record: Dict[str, Any] = {
        "event": f"webhook-dispatcher-{kind}",
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
    }
    if endpoint is not None:
        record["endpoint_id"] = endpoint.endpoint_id
        record["url"] = endpoint.url
        record["endpoint_digest"] = endpoint.digest
    if delivery is not None:
        record["delivery_id"] = delivery.delivery_id
        record["endpoint_id"] = delivery.endpoint_id
        record["event_type"] = delivery.event_type
        record["payload_digest"] = delivery.payload_digest
        record["attempt"] = delivery.attempt
        record["status"] = delivery.status
        record["delivery_digest"] = delivery.digest
    if decision is not None:
        record["delivery_id"] = decision.delivery_id
        record["attempt"] = decision.attempt
        record["status"] = decision.status
        record["backoff_seqs"] = decision.backoff_seqs
    return record


def main() -> None:
    """Self-check: registration, signing, verification, retry ledger."""
    d = WebhookDispatcher()

    ep = d.register("stripe", "https://example.com/hooks", "s3cr3t", 0)
    assert ep.endpoint_id == "stripe"
    assert "s3cr3t" not in repr(ep.as_dict())
    assert "s3cr3t" not in str(ep.as_dict())

    try:
        d.register("stripe", "https://example.com/other", "x", 1)
    except DuplicateEndpointError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected DuplicateEndpointError")

    for bad_url in ("http://example.com/hooks", "https://user:pw@example.com/h"):
        try:
            d.register("bad", bad_url, "x", 1)
        except WebhookError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"expected WebhookError for {bad_url}")

    payload = {"id": "evt_1", "amount": 100}
    rec = d.dispatch("stripe", "payment.succeeded", payload, 2)
    assert rec.signature.startswith("sha256=")
    assert rec.status == "scheduled"
    assert rec.attempt == 0

    assert verify_sig("s3cr3t", payload, rec.signature) is True
    assert verify_sig("wrong", payload, rec.signature) is False
    assert verify_sig("s3cr3t", {"id": "evt_2"}, rec.signature) is False
    assert verify_sig("s3cr3t", payload, "not-a-signature") is False
    assert verify_sig("s3cr3t", payload, "sha256=" + "zz" * 32) is False

    rep = d.verify_delivery(rec.delivery_id, payload, rec.signature)
    assert rep.valid is True

    try:
        d.dispatch("ghost", "x", {}, 3)
    except UnknownEndpointError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected UnknownEndpointError")

    # retry ledger: 4 failures -> retrying with growing backoff, 5th -> dead
    backoffs = []
    for i in range(4):
        dec = d.report(rec.delivery_id, False, 10 + i)
        assert dec.status == "retrying"
        backoffs.append(dec.backoff_seqs)
    assert backoffs == [1, 2, 4, 8]
    dec = d.report(rec.delivery_id, False, 14)
    assert dec.status == "dead" and dec.backoff_seqs == 0
    assert d.delivery_status(rec.delivery_id) == "dead"

    try:
        d.report(rec.delivery_id, True, 15)
    except TerminalDeliveryError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected TerminalDeliveryError")

    rec2 = d.dispatch("stripe", "payment.failed", {"id": "evt_3"}, 20)
    dec2 = d.report(rec2.delivery_id, True, 21)
    assert dec2.status == "delivered"
    assert d.pending() == ()

    try:
        d.report("dlv-999", True, 22)
    except UnknownDeliveryError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected UnknownDeliveryError")

    print(
        "webhook-dispatcher OK: register, sign, verify, retry ledger, dead-letter"
    )


if __name__ == "__main__":
    main()
