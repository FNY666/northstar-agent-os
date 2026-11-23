"""Webhook registration and delivery bookkeeping: retries with a ledger.

A ``WebhookManager`` books host-reported webhook delivery decisions as a
deterministic single-host state machine:

- ``register(webhook_id, url, seq, events=(), secret=None)`` pins an
  endpoint. URLs must be ``https://`` (``http://`` refused fail-closed);
  secret material is stored only as a domain-separated digest, never in
  records or audit events.
- ``deliver(webhook_id, event, payload_digest, seq)`` books one delivery
  attempt as a frozen ``DeliveryRecord`` (``dlv-N`` ids). The outcome is
  produced by a host-injectable ``transport(webhook, event, attempt) ->
  bool`` (default: always succeeds, in memory). A failed attempt is
  *data* (``status="failed"``), not an exception; delivery is simulated.
- ``retry(delivery_id, seq)`` books a follow-up attempt linked to the
  prior one via ``prev_delivery_id``. Retrying an already-delivered
  delivery raises ``AlreadyDeliveredError``; exceeding ``max_attempts``
  raises ``MaxAttemptsError``.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``webhook-manager.v1``, schema pin ``northstar.webhook-manager.v1``,
``main()`` self-check.

Honest scope: this module books *delivery decisions*, not deliveries —
there is no network, no HTTP client, no actual retry timer. The default
transport is a stub; a host transport reports its own truth (GIGO). The
signature header helper ``signature_for()`` computes HMAC-SHA256 the way
a sender would, so hosts can verify consistency; it does not prove the
receiver verified anything.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
WEBHOOK_MANAGER_VERSION = "webhook-manager.v1"

#: Schema pin carried by records and audit events.
WEBHOOK_MANAGER_SCHEMA = "northstar.webhook-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_GENESIS = "genesis"

#: Pin: delivery statuses.
STATUSES = ("delivered", "failed", "pending")

#: Pin: maximum delivery attempts per delivery chain.
MAX_ATTEMPTS = 5

#: Pin: allowed URL schemes.
_URL_SCHEMES = ("https://",)


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class WebhookManagerError(Exception):
    """Base class for all webhook_manager errors."""


class UnknownWebhookError(WebhookManagerError):
    """The referenced webhook id is not registered."""


class DuplicateWebhookError(WebhookManagerError):
    """A webhook with this id is already registered."""


class BadWebhookError(WebhookManagerError):
    """The registration request is malformed (URL, events, or secret)."""


class UnknownDeliveryError(WebhookManagerError):
    """The referenced delivery id is unknown."""


class AlreadyDeliveredError(WebhookManagerError):
    """Retrying a delivery whose final attempt already delivered."""


class MaxAttemptsError(WebhookManagerError):
    """The delivery chain already used MAX_ATTEMPTS attempts."""


class BadDeliveryError(WebhookManagerError):
    """The deliver/retry request is malformed."""


class SeqOrderError(WebhookManagerError):
    """A mutation seq was not strictly increasing, or not an int."""


class AuditKindError(WebhookManagerError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------


def _tag_encode(value: Any) -> Any:
    if value is True:
        return {"$bool": True}
    if value is False:
        return {"$bool": False}
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadWebhookError("integer out of safe range")
        return {"$int": value}
    if isinstance(value, float):
        raise BadWebhookError("floats are not permitted in pinned structures")
    if isinstance(value, (list, tuple)):
        return [_tag_encode(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _tag_encode(v) for k, v in value.items()}
    if isinstance(value, (str, type(None))):
        return value
    raise BadWebhookError(f"unsupported value type: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    canonical = jcs_canonical_json(_tag_encode(list(parts)))
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _secret_digest(secret: str, salt: str) -> str:
    return "sha256:" + hmac.new(
        salt.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256
    ).hexdigest()


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "webhook-registered",
    "delivered",
    "failed",
    "retried",
    "rejected",
)


def webhook_manager_audit_event(
    kind: str, seq: int, webhook_id: str = "", delivery_id: str = "", detail: str = ""
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event; ids and digest pins only."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return {
        "schema": AUDIT_SCHEMA,
        "module": WEBHOOK_MANAGER_VERSION,
        "kind": kind,
        "seq": seq,
        "webhook_id": webhook_id,
        "delivery_id": delivery_id,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WebhookRecord:
    webhook_id: str
    url: str
    events: Tuple[str, ...]
    seq: int
    digest: str
    secret_digest: str = ""

    def verify(self) -> bool:
        return self.digest == _pin(
            WEBHOOK_MANAGER_SCHEMA,
            self.webhook_id,
            self.url,
            list(self.events),
            self.seq,
            self.secret_digest,
        )


@dataclass(frozen=True)
class DeliveryRecord:
    delivery_id: str
    webhook_id: str
    event: str
    payload_digest: str
    attempt: int
    status: str
    seq: int
    prev_delivery_id: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            WEBHOOK_MANAGER_SCHEMA,
            self.delivery_id,
            self.webhook_id,
            self.event,
            self.payload_digest,
            self.attempt,
            self.status,
            self.seq,
            self.prev_delivery_id,
        )


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


def _default_transport(
    webhook: WebhookRecord, event: str, attempt: int
) -> bool:
    return True


class WebhookManager:
    """Deterministic webhook delivery bookkeeping ledger."""

    def __init__(
        self,
        seed: str = "",
        transport: Optional[Callable[[WebhookRecord, str, int], bool]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._transport = transport or _default_transport
        self._webhooks: Dict[str, WebhookRecord] = {}
        self._deliveries: Dict[str, DeliveryRecord] = {}
        self._chains: Dict[str, List[str]] = {}  # root delivery id -> attempt ids
        self._last_seq = -1
        self._w_counter = 0
        self._d_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _check_seq(self, seq: Any) -> None:
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (got {seq}, last {self._last_seq})"
            )
        self._last_seq = seq

    def _reject(self, seq: int, reason: str) -> None:
        try:
            self._check_seq(seq)
        except SeqOrderError:
            pass
        self._audit.append(
            webhook_manager_audit_event("rejected", seq, detail=reason)
        )

    def _salt(self) -> str:
        return _pin(WEBHOOK_MANAGER_SCHEMA, "secret-salt", self._seed)

    # -- public API -----------------------------------------------------

    def register(
        self,
        webhook_id: str,
        url: str,
        seq: int,
        events: Sequence[str] = (),
        secret: Optional[str] = None,
    ) -> WebhookRecord:
        """Pin an endpoint; ``http://`` URLs and duplicate ids are refused."""
        with self._lock:
            try:
                self._check_seq(seq)
            except SeqOrderError:
                self._reject(seq if isinstance(seq, int) and not isinstance(seq, bool) else 0,
                             "seq-order")
                raise
            if not isinstance(webhook_id, str) or not webhook_id:
                self._reject(seq, "bad-webhook-id")
                raise BadWebhookError("webhook_id must be a non-empty string")
            if webhook_id in self._webhooks:
                self._reject(seq, "duplicate-webhook")
                raise DuplicateWebhookError(f"webhook already registered: {webhook_id}")
            if not isinstance(url, str) or not url.startswith(_URL_SCHEMES):
                self._reject(seq, "bad-url")
                raise BadWebhookError("url must start with https://")
            if not isinstance(events, (list, tuple)) or any(
                not isinstance(e, str) or not e for e in events
            ):
                self._reject(seq, "bad-events")
                raise BadWebhookError("events must be a sequence of non-empty strings")
            secret_digest = ""
            if secret is not None:
                if not isinstance(secret, str) or len(secret) < 16:
                    self._reject(seq, "bad-secret")
                    raise BadWebhookError("secret must be a string of >= 16 chars")
                secret_digest = _secret_digest(secret, self._salt())
            record = WebhookRecord(
                webhook_id=webhook_id,
                url=url,
                events=tuple(events),
                seq=seq,
                digest="",
                secret_digest=secret_digest,
            )
            digest = _pin(
                WEBHOOK_MANAGER_SCHEMA,
                webhook_id,
                url,
                list(events),
                seq,
                secret_digest,
            )
            record = WebhookRecord(
                webhook_id=webhook_id,
                url=url,
                events=tuple(events),
                seq=seq,
                digest=digest,
                secret_digest=secret_digest,
            )
            self._webhooks[webhook_id] = record
            self._w_counter += 1
            self._audit.append(
                webhook_manager_audit_event(
                    "webhook-registered", seq, webhook_id=webhook_id
                )
            )
            return record

    def deliver(
        self, webhook_id: str, event: str, payload_digest: str, seq: int
    ) -> DeliveryRecord:
        """Book one delivery attempt; transport failure is data, not raised."""
        with self._lock:
            try:
                self._check_seq(seq)
            except SeqOrderError:
                self._reject(seq if isinstance(seq, int) and not isinstance(seq, bool) else 0,
                             "seq-order")
                raise
            webhook = self._webhooks.get(webhook_id)
            if webhook is None:
                self._reject(seq, "unknown-webhook")
                raise UnknownWebhookError(f"unknown webhook: {webhook_id}")
            if not isinstance(event, str) or not event:
                self._reject(seq, "bad-event")
                raise BadDeliveryError("event must be a non-empty string")
            if (
                not isinstance(payload_digest, str)
                or not payload_digest.startswith("sha256:")
                or len(payload_digest) != len("sha256:") + 64
            ):
                self._reject(seq, "bad-payload-digest")
                raise BadDeliveryError("payload_digest must be 'sha256:' + 64 hex chars")
            self._d_counter += 1
            delivery_id = f"dlv-{self._d_counter}"
            try:
                ok = bool(self._transport(webhook, event, 1))
            except Exception:
                ok = False  # fail-closed: a raising transport counts as failure
            status = "delivered" if ok else "failed"
            digest = _pin(
                WEBHOOK_MANAGER_SCHEMA,
                delivery_id,
                webhook_id,
                event,
                payload_digest,
                1,
                status,
                seq,
                "",
            )
            record = DeliveryRecord(
                delivery_id=delivery_id,
                webhook_id=webhook_id,
                event=event,
                payload_digest=payload_digest,
                attempt=1,
                status=status,
                seq=seq,
                prev_delivery_id="",
                digest=digest,
            )
            self._deliveries[delivery_id] = record
            self._chains[delivery_id] = [delivery_id]
            self._audit.append(
                webhook_manager_audit_event(
                    "delivered" if ok else "failed",
                    seq,
                    webhook_id=webhook_id,
                    delivery_id=delivery_id,
                )
            )
            return record

    def retry(self, delivery_id: str, seq: int) -> DeliveryRecord:
        """Book a follow-up attempt for a failed delivery."""
        with self._lock:
            try:
                self._check_seq(seq)
            except SeqOrderError:
                self._reject(seq if isinstance(seq, int) and not isinstance(seq, bool) else 0,
                             "seq-order")
                raise
            head = self._deliveries.get(delivery_id)
            if head is None:
                self._reject(seq, "unknown-delivery")
                raise UnknownDeliveryError(f"unknown delivery: {delivery_id}")
            if head.status == "delivered":
                self._reject(seq, "already-delivered")
                raise AlreadyDeliveredError(
                    f"delivery already delivered: {delivery_id}"
                )
            if head.attempt >= MAX_ATTEMPTS:
                self._reject(seq, "max-attempts")
                raise MaxAttemptsError(
                    f"delivery exceeded {MAX_ATTEMPTS} attempts: {delivery_id}"
                )
            webhook = self._webhooks[head.webhook_id]
            root = self._chain_root(delivery_id)
            attempt = head.attempt + 1
            try:
                ok = bool(self._transport(webhook, head.event, attempt))
            except Exception:
                ok = False
            status = "delivered" if ok else "failed"
            self._d_counter += 1
            new_id = f"dlv-{self._d_counter}"
            digest = _pin(
                WEBHOOK_MANAGER_SCHEMA,
                new_id,
                head.webhook_id,
                head.event,
                head.payload_digest,
                attempt,
                status,
                seq,
                delivery_id,
            )
            record = DeliveryRecord(
                delivery_id=new_id,
                webhook_id=head.webhook_id,
                event=head.event,
                payload_digest=head.payload_digest,
                attempt=attempt,
                status=status,
                seq=seq,
                prev_delivery_id=delivery_id,
                digest=digest,
            )
            self._deliveries[new_id] = record
            self._chains[root].append(new_id)
            self._audit.append(
                webhook_manager_audit_event(
                    "delivered" if ok else "failed",
                    seq,
                    webhook_id=head.webhook_id,
                    delivery_id=new_id,
                    detail="retry",
                )
            )
            return record

    def signature_for(self, webhook_id: str, payload_digest: str) -> str:
        """Compute the HMAC-SHA256 signature a sender would attach.

        Pure view: validates nothing about the wire, consumes no seq.
        Requires a secret to have been registered with the webhook.
        """
        webhook = self._webhooks.get(webhook_id)
        if webhook is None:
            raise UnknownWebhookError(f"unknown webhook: {webhook_id}")
        if not webhook.secret_digest:
            raise BadWebhookError("webhook has no registered secret")
        return "sha256=" + hmac.new(
            webhook.secret_digest.encode("utf-8"),
            payload_digest.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    # -- views (pure; consume no seq) -----------------------------------

    def _chain_root(self, delivery_id: str) -> str:
        for root, ids in self._chains.items():
            if delivery_id in ids:
                return root
        return delivery_id

    def webhook(self, webhook_id: str) -> WebhookRecord:
        record = self._webhooks.get(webhook_id)
        if record is None:
            raise UnknownWebhookError(f"unknown webhook: {webhook_id}")
        return record

    def delivery(self, delivery_id: str) -> DeliveryRecord:
        record = self._deliveries.get(delivery_id)
        if record is None:
            raise UnknownDeliveryError(f"unknown delivery: {delivery_id}")
        return record

    def webhook_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._webhooks))

    def delivery_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._deliveries))

    def attempts_for(self, root_delivery_id: str) -> Tuple[str, ...]:
        return tuple(self._chains.get(root_delivery_id, ()))

    def stats(self) -> Dict[str, int]:
        delivered = sum(1 for d in self._deliveries.values() if d.status == "delivered")
        failed = sum(1 for d in self._deliveries.values() if d.status == "failed")
        return {
            "webhooks": len(self._webhooks),
            "deliveries": len(self._deliveries),
            "delivered": delivered,
            "failed": failed,
        }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        return tuple(self._audit)


# ---------------------------------------------------------------------------
# main() self-check
# ---------------------------------------------------------------------------


def main() -> None:
    def fail_first(webhook: WebhookRecord, event: str, attempt: int) -> bool:
        return attempt > 1

    mgr = WebhookManager(seed="selfcheck", transport=fail_first)
    digest = "sha256:" + "ab" * 32
    mgr.register("wh-1", "https://example.com/hook", 1, events=("order.created",),
                 secret="super-secret-value-16")
    d1 = mgr.deliver("wh-1", "order.created", digest, 2)
    assert d1.status == "failed", d1.status
    assert d1.attempt == 1
    d2 = mgr.retry(d1.delivery_id, 3)
    assert d2.status == "delivered", d2.status
    assert d2.attempt == 2
    assert d2.prev_delivery_id == d1.delivery_id
    assert d2.verify() and d1.verify()
    assert mgr.webhook("wh-1").verify()
    assert mgr.attempts_for(d1.delivery_id) == (d1.delivery_id, d2.delivery_id)
    sig = mgr.signature_for("wh-1", digest)
    assert sig.startswith("sha256=") and len(sig) == len("sha256=") + 64
    try:
        mgr.retry(d2.delivery_id, 4)
    except AlreadyDeliveredError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected AlreadyDeliveredError")
    print("webhook-manager OK: register, deliver, retry, pins, audit")


if __name__ == "__main__":
    main()
