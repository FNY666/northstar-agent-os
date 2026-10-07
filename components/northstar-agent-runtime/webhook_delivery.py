"""Webhook delivery attempts and signature verification: Svix-shaped bookkeeping.

A ``WebhookDelivery`` books webhook delivery decisions as a deterministic
single-host state machine, deliberately distinct from ``webhook_manager``
(which owns endpoint registration and host transport delivery):

- ``dispatch(message_id, payload_digest, seq)`` books a message queued for
  delivery. The payload itself is booked by digest only — bytes never
  cross the module boundary.
- ``send(message_id, endpoint_url, seq, secret=None)`` books one delivery
  attempt as a frozen ``AttemptRecord`` (``att-N`` ids). The outcome comes
  from a host-injectable ``transporter(endpoint_url, payload_digest,
  attempt_no) -> bool`` (default: always succeeds in memory). A failed
  attempt is *data* (``status="failed"``), never raised; a raising
  transporter counts as failure (fail-closed). Delivery is simulated.
- ``retry(attempt_id, seq)`` books a follow-up attempt linked via
  ``prev_attempt_id`` with a deterministic logical backoff
  (``backoff_seq = 2 ** (attempt_no - 1)`` — logical seq units, no
  timers). Retrying a delivered chain raises ``AlreadyDeliveredError``;
  exceeding ``MAX_ATTEMPTS`` raises ``MaxAttemptsError``.
- ``verify(signed_content, signature_header, secret, seq, timestamp_seq,
  max_skew=300)`` is a pure read view (validates seq shape, consumes
  nothing, writes no audit row) verifying Svix-style ``v1,<base64>``
  HMAC-SHA256 signatures with ``hmac.compare_digest``. A non-matching
  signature or a timestamp outside the skew window is *data*
  (``valid=False`` with a reason), not an exception; malformed caller
  inputs raise ``BadSignatureError`` fail-closed.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``webhook-delivery.v1``, schema pin ``northstar.webhook-delivery.v1``,
``main()`` self-check.

Honest scope: this module books *delivery decisions*, not deliveries —
there is no network, no HTTP client, no actual retry timer, and no key
server. ``verify()`` checks that a presented signature matches a
presented secret; it cannot prove the sender is who they claim to be,
and secret material never enters a record or the audit boundary.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
WEBHOOK_DELIVERY_VERSION = "webhook-delivery.v1"

#: Schema pin carried by records and audit events.
WEBHOOK_DELIVERY_SCHEMA = "northstar.webhook-delivery.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_GENESIS = "genesis"

#: Pin: delivery attempt statuses.
STATUSES = ("delivered", "failed")

#: Pin: maximum attempts per delivery chain.
MAX_ATTEMPTS = 5

#: Pin: signature scheme prefix accepted by verify().
_SIG_SCHEME = "v1"

#: Pin: default timestamp skew window, in logical seq units.
DEFAULT_MAX_SKEW = 300

#: Pin: verification failure reasons.
VERIFY_REASONS = ("ok", "signature-mismatch", "stale")


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class WebhookDeliveryError(Exception):
    """Base class for all webhook_delivery errors."""


class UnknownMessageError(WebhookDeliveryError):
    """The referenced message id is unknown."""


class DuplicateMessageError(WebhookDeliveryError):
    """A message with this id is already dispatched."""


class BadMessageError(WebhookDeliveryError):
    """The dispatch request is malformed (id or payload digest)."""


class BadEndpointError(WebhookDeliveryError):
    """The endpoint URL is malformed (must be https://)."""


class BadAttemptError(WebhookDeliveryError):
    """The send/retry request is malformed."""


class UnknownAttemptError(WebhookDeliveryError):
    """The referenced attempt id is unknown."""


class AlreadyDeliveredError(WebhookDeliveryError):
    """Retrying a delivery chain whose latest attempt already delivered."""


class MaxAttemptsError(WebhookDeliveryError):
    """The delivery chain already used MAX_ATTEMPTS attempts."""


class BadSignatureError(WebhookDeliveryError):
    """The verify() caller inputs are malformed (types, empty secret,
    malformed signature header)."""


class SeqOrderError(WebhookDeliveryError):
    """A mutation seq was not strictly increasing, or not an int."""


class AuditKindError(WebhookDeliveryError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([WEBHOOK_DELIVERY_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WebhookDeliveryError(f"{name} must be a non-empty string")
    return value.strip()


def _check_digest(value: Any, name: str) -> str:
    text = _check_nonempty_str(value, name)
    if not text.startswith("sha256:") or len(text) != len("sha256:") + 64:
        raise WebhookDeliveryError(
            f"{name} must be a sha256: digest pin"
        )
    try:
        int(text[len("sha256:"):], 16)
    except ValueError:
        raise WebhookDeliveryError(f"{name} must be a sha256: digest pin")
    return text


def _check_url(value: Any, name: str) -> str:
    text = _check_nonempty_str(value, name)
    if not text.startswith("https://") or len(text) > 2048:
        raise BadEndpointError(
            f"{name} must be an https:// URL (<=2048 chars)"
        )
    if any(ch.isspace() for ch in text):
        raise BadEndpointError(f"{name} must not contain whitespace")
    return text


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MessageRecord:
    """One dispatched message (frozen). Payload booked by digest only."""

    message_id: str
    payload_digest: str
    seq: int
    digest: str
    schema: str = WEBHOOK_DELIVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "message", self.message_id, self.payload_digest, self.seq
        )


@dataclass(frozen=True)
class AttemptRecord:
    """One delivery attempt (frozen). Outcome is data, never raised."""

    attempt_id: str
    message_id: str
    endpoint_url: str
    attempt_no: int
    status: str
    backoff_seq: int
    prev_attempt_id: str
    seq: int
    digest: str
    schema: str = WEBHOOK_DELIVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "attempt", self.attempt_id, self.message_id, self.endpoint_url,
            self.attempt_no, self.status, self.backoff_seq,
            self.prev_attempt_id, self.seq,
        )


@dataclass(frozen=True)
class VerificationResult:
    """One signature verification verdict (frozen). ``valid=False`` is data."""

    signed_content_digest: str
    valid: bool
    reason: str
    seq: int
    digest: str
    schema: str = WEBHOOK_DELIVERY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "verification", self.signed_content_digest, self.valid,
            self.reason, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_DISPATCHED = "webhook-delivery.dispatched"
KIND_ATTEMPTED = "webhook-delivery.attempted"
KIND_RETRIED = "webhook-delivery.retried"
KIND_REJECTED = "webhook-delivery.rejected"
_KINDS = (KIND_DISPATCHED, KIND_ATTEMPTED, KIND_RETRIED, KIND_REJECTED)


def webhook_delivery_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the webhook-delivery module."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise WebhookDeliveryError("detail must be a mapping")
    # Secrets, payloads and signatures never cross the audit boundary.
    banned = {"secret", "payload", "payload_digest", "signature",
              "signature_header", "signed_content"}
    if any(k in detail for k in banned):
        raise WebhookDeliveryError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": WEBHOOK_DELIVERY_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------

#: Default transporter: always succeeds (in-memory simulation).
def _default_transporter(
    endpoint_url: str, payload_digest: str, attempt_no: int
) -> bool:
    return True


class WebhookDelivery:
    """Deterministic webhook delivery-attempt ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume their
    seq (fail-closed ledger position). ``verify()`` is a pure read view.
    """

    def __init__(
        self,
        transporter: Optional[
            Callable[[str, str, int], bool]
        ] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._transporter = transporter or _default_transporter
        self._messages: Dict[str, MessageRecord] = {}
        self._attempts: Dict[str, AttemptRecord] = {}
        self._chain_heads: Dict[Tuple[str, str], str] = {}
        self._seq = 0
        self._next_attempt = 0
        self._audit: List[Dict[str, Any]] = []
        self._chained_digest = _GENESIS

    # -- internals ------------------------------------------------------

    def _use_seq(self, seq: int) -> None:
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} is not strictly greater than {self._seq}"
            )
        self._seq = seq

    def _reject(self, seq: int, reason: str) -> None:
        self._audit.append(
            webhook_delivery_audit_event(
                KIND_REJECTED, {"reason": reason}, seq
            )
        )

    def _chain(self, record_digest: str) -> str:
        self._chained_digest = hashlib.sha256(
            (self._chained_digest + record_digest).encode("utf-8")
        ).hexdigest()
        return self._chained_digest

    # -- mutations ------------------------------------------------------

    def dispatch(self, message_id: str, payload_digest: str, seq: int) -> MessageRecord:
        """Book a message queued for delivery."""
        _check_seq(seq, "seq")
        try:
            mid = _check_nonempty_str(message_id, "message_id")
            pd = _check_digest(payload_digest, "payload_digest")
        except WebhookDeliveryError as exc:
            with self._lock:
                self._use_seq(seq)
                self._reject(seq, str(exc))
            if isinstance(exc, (BadMessageError,)):
                raise
            raise BadMessageError(str(exc))
        with self._lock:
            self._use_seq(seq)
            if mid in self._messages:
                self._reject(seq, "duplicate message")
                raise DuplicateMessageError(f"message {mid!r} already dispatched")
            record = MessageRecord(
                message_id=mid,
                payload_digest=pd,
                seq=seq,
                digest=_pin("message", mid, pd, seq),
            )
            self._messages[mid] = record
            self._audit.append(
                webhook_delivery_audit_event(
                    KIND_DISPATCHED,
                    {"message_id": mid, "digest": record.digest},
                    seq,
                )
            )
            return record

    def send(
        self,
        message_id: str,
        endpoint_url: str,
        seq: int,
        secret: Optional[str] = None,
    ) -> AttemptRecord:
        """Book one delivery attempt for a message to an endpoint.

        The outcome comes from the host-injectable transporter; failure is
        data. ``secret``, when given, is pinned only as a digest and never
        stored in the record or the audit boundary.
        """
        _check_seq(seq, "seq")
        try:
            mid = _check_nonempty_str(message_id, "message_id")
            url = _check_url(endpoint_url, "endpoint_url")
            if secret is not None and (
                not isinstance(secret, str) or not secret
            ):
                raise BadAttemptError("secret must be a non-empty string")
        except WebhookDeliveryError as exc:
            with self._lock:
                self._use_seq(seq)
                self._reject(seq, str(exc))
            if isinstance(exc, (BadAttemptError, BadEndpointError)):
                raise
            raise BadAttemptError(str(exc))
        with self._lock:
            self._use_seq(seq)
            message = self._messages.get(mid)
            if message is None:
                self._reject(seq, "unknown message")
                raise UnknownMessageError(f"message {mid!r} is unknown")
            key = (mid, url)
            if key in self._chain_heads:
                self._reject(seq, "chain already started; use retry()")
                raise BadAttemptError(
                    f"delivery to {url!r} already started; use retry()"
                )
            self._next_attempt += 1
            attempt_no = 1
            try:
                delivered = bool(
                    self._transporter(url, message.payload_digest, attempt_no)
                )
            except Exception:
                delivered = False  # raising transporter = failure, fail-closed
            record = AttemptRecord(
                attempt_id=f"att-{self._next_attempt}",
                message_id=mid,
                endpoint_url=url,
                attempt_no=attempt_no,
                status="delivered" if delivered else "failed",
                backoff_seq=1,
                prev_attempt_id="",
                seq=seq,
                digest=_pin(
                    "attempt", f"att-{self._next_attempt}", mid, url,
                    attempt_no, "delivered" if delivered else "failed",
                    1, "", seq,
                ),
            )
            self._attempts[record.attempt_id] = record
            self._chain_heads[key] = record.attempt_id
            self._chain(record.digest)
            self._audit.append(
                webhook_delivery_audit_event(
                    KIND_ATTEMPTED,
                    {
                        "attempt_id": record.attempt_id,
                        "message_id": mid,
                        "attempt_no": attempt_no,
                        "status": record.status,
                        "digest": record.digest,
                    },
                    seq,
                )
            )
            return record

    def retry(self, attempt_id: str, seq: int) -> AttemptRecord:
        """Book a follow-up attempt linked to the chain head's predecessor."""
        _check_seq(seq, "seq")
        aid = _check_nonempty_str(attempt_id, "attempt_id")
        with self._lock:
            self._use_seq(seq)
            prev = self._attempts.get(aid)
            if prev is None:
                self._reject(seq, "unknown attempt")
                raise UnknownAttemptError(f"attempt {aid!r} is unknown")
            head = self._chain_heads.get((prev.message_id, prev.endpoint_url))
            if head != aid:
                self._reject(seq, "not the chain head")
                raise BadAttemptError(
                    f"attempt {aid!r} is not the chain head; retry the head"
                )
            if prev.status == "delivered":
                self._reject(seq, "already delivered")
                raise AlreadyDeliveredError(
                    f"attempt {aid!r} already delivered"
                )
            if prev.attempt_no >= MAX_ATTEMPTS:
                self._reject(seq, "max attempts exceeded")
                raise MaxAttemptsError(
                    f"delivery chain already used {MAX_ATTEMPTS} attempts"
                )
            message = self._messages[prev.message_id]
            attempt_no = prev.attempt_no + 1
            backoff = 2 ** (attempt_no - 1)
            try:
                delivered = bool(
                    self._transporter(
                        prev.endpoint_url, message.payload_digest, attempt_no
                    )
                )
            except Exception:
                delivered = False
            self._next_attempt += 1
            record = AttemptRecord(
                attempt_id=f"att-{self._next_attempt}",
                message_id=prev.message_id,
                endpoint_url=prev.endpoint_url,
                attempt_no=attempt_no,
                status="delivered" if delivered else "failed",
                backoff_seq=backoff,
                prev_attempt_id=aid,
                seq=seq,
                digest=_pin(
                    "attempt", f"att-{self._next_attempt}", prev.message_id,
                    prev.endpoint_url, attempt_no,
                    "delivered" if delivered else "failed", backoff, aid, seq,
                ),
            )
            self._attempts[record.attempt_id] = record
            self._chain_heads[(prev.message_id, prev.endpoint_url)] = (
                record.attempt_id
            )
            self._chain(record.digest)
            self._audit.append(
                webhook_delivery_audit_event(
                    KIND_RETRIED,
                    {
                        "attempt_id": record.attempt_id,
                        "prev_attempt_id": aid,
                        "attempt_no": attempt_no,
                        "status": record.status,
                        "backoff_seq": backoff,
                        "digest": record.digest,
                    },
                    seq,
                )
            )
            return record

    # -- pure read views ------------------------------------------------

    def verify(
        self,
        signed_content: str,
        signature_header: str,
        secret: str,
        seq: int,
        timestamp_seq: int,
        max_skew: int = DEFAULT_MAX_SKEW,
    ) -> VerificationResult:
        """Verify an Svix-style ``v1,<base64>`` signature (pure read view).

        Validates ``seq`` shape but consumes nothing and writes no audit
        row. A non-matching signature or a timestamp outside the skew
        window is returned as data (``valid=False``); malformed caller
        inputs raise ``BadSignatureError`` fail-closed.
        """
        _check_seq(seq, "seq")
        _check_seq(timestamp_seq, "timestamp_seq")
        if isinstance(max_skew, bool) or not isinstance(max_skew, int) or max_skew < 0:
            raise BadSignatureError("max_skew must be a non-negative int")
        if not isinstance(signed_content, str) or not signed_content:
            raise BadSignatureError("signed_content must be a non-empty string")
        if not isinstance(signature_header, str) or not signature_header.strip():
            raise BadSignatureError(
                "signature_header must be a non-empty string"
            )
        if not isinstance(secret, str) or not secret:
            raise BadSignatureError("secret must be a non-empty string")
        content_digest = _pin("verify-content", signed_content)
        stale = abs(seq - timestamp_seq) > max_skew
        expected = base64.b64encode(
            hmac.new(
                secret.encode("utf-8"),
                signed_content.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        ).decode("ascii")
        matched = False
        for token in signature_header.split():
            if not token.startswith(_SIG_SCHEME + ","):
                continue
            candidate = token[len(_SIG_SCHEME) + 1:]
            if hmac.compare_digest(candidate, expected):
                matched = True
                break
        if stale:
            valid, reason = False, "stale"
        elif matched:
            valid, reason = True, "ok"
        else:
            valid, reason = False, "signature-mismatch"
        return VerificationResult(
            signed_content_digest=content_digest,
            valid=valid,
            reason=reason,
            seq=seq,
            digest=_pin("verification", content_digest, valid, reason, seq),
        )

    def message(self, message_id: str) -> MessageRecord:
        """Pure lookup of a dispatched message."""
        mid = _check_nonempty_str(message_id, "message_id")
        with self._lock:
            record = self._messages.get(mid)
            if record is None:
                raise UnknownMessageError(f"message {mid!r} is unknown")
            return record

    def message_ids(self) -> List[str]:
        """Pure view of dispatched message ids, sorted."""
        with self._lock:
            return sorted(self._messages)

    def attempt(self, attempt_id: str) -> AttemptRecord:
        """Pure lookup of one attempt record."""
        aid = _check_nonempty_str(attempt_id, "attempt_id")
        with self._lock:
            record = self._attempts.get(aid)
            if record is None:
                raise UnknownAttemptError(f"attempt {aid!r} is unknown")
            return record

    def attempts_for(self, message_id: str) -> List[AttemptRecord]:
        """Pure view of a message's attempts, oldest first."""
        mid = _check_nonempty_str(message_id, "message_id")
        with self._lock:
            if mid not in self._messages:
                raise UnknownMessageError(f"message {mid!r} is unknown")
            records = [
                a for a in self._attempts.values() if a.message_id == mid
            ]
            return sorted(records, key=lambda a: a.attempt_no)

    def stats(self) -> Dict[str, int]:
        """Pure view of ledger counts."""
        with self._lock:
            delivered = sum(
                1 for a in self._attempts.values()
                if a.status == "delivered"
            )
            return {
                "messages": len(self._messages),
                "attempts": len(self._attempts),
                "delivered": delivered,
                "failed": len(self._attempts) - delivered,
                "audit_events": len(self._audit),
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        """Pure view of the audit event list (copy)."""
        with self._lock:
            return list(self._audit)

    def as_dict(self) -> Dict[str, Any]:
        """Pure snapshot of the ledger (digests only where secrets apply)."""
        with self._lock:
            return {
                "schema": WEBHOOK_DELIVERY_SCHEMA,
                "version": WEBHOOK_DELIVERY_VERSION,
                "messages": [
                    {
                        "message_id": m.message_id,
                        "payload_digest": m.payload_digest,
                        "seq": m.seq,
                        "digest": m.digest,
                    }
                    for m in sorted(
                        self._messages.values(), key=lambda m: m.message_id
                    )
                ],
                "attempts": [
                    {
                        "attempt_id": a.attempt_id,
                        "message_id": a.message_id,
                        "attempt_no": a.attempt_no,
                        "status": a.status,
                        "backoff_seq": a.backoff_seq,
                        "digest": a.digest,
                    }
                    for a in sorted(
                        self._attempts.values(),
                        key=lambda a: a.attempt_no,
                    )
                ],
            }


def _stdlib_only_ok() -> bool:
    """AST check that this module imports only the stdlib."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8")
    )
    allowed = {
        "__future__", "ast", "base64", "dataclasses", "hashlib", "hmac",
        "json", "pathlib", "threading", "typing",
    }
    imported: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module == "canonical_json":
                continue  # guarded fallback, house pattern
            if node.module:
                imported.add(node.module.split(".")[0])
    return imported <= allowed


def main() -> None:
    """Self-check: dispatch, send, retry, verify, pins, audit."""
    ledger = WebhookDelivery()
    msg = ledger.dispatch("m-1", "sha256:" + "ab" * 32, 1)
    assert msg.verify()
    att = ledger.send("m-1", "https://example.com/hook", 2)
    assert att.status == "delivered" and att.attempt_no == 1
    assert att.verify()

    flaky = WebhookDelivery(
        transporter=lambda url, digest, n: n >= 2
    )
    flaky.dispatch("m-2", "sha256:" + "cd" * 32, 1)
    first = flaky.send("m-2", "https://example.com/hook", 2)
    assert first.status == "failed"
    second = flaky.retry(first.attempt_id, 3)
    assert second.status == "delivered"
    assert second.prev_attempt_id == first.attempt_id
    assert second.backoff_seq == 2

    signed = "m-2.100.payload"
    sig = base64.b64encode(
        hmac.new(b"s3cr3t", signed.encode(), hashlib.sha256).digest()
    ).decode("ascii")
    ok = ledger.verify(signed, f"v1,{sig}", "s3cr3t", 100, 100)
    assert ok.valid and ok.reason == "ok" and ok.verify()
    bad = ledger.verify(signed, "v1," + "A" * 44, "s3cr3t", 100, 100)
    assert not bad.valid and bad.reason == "signature-mismatch"
    stale = ledger.verify(signed, f"v1,{sig}", "s3cr3t", 1000, 100)
    assert not stale.valid and stale.reason == "stale"

    kinds = {e["kind"] for e in ledger.audit_log()}
    assert KIND_DISPATCHED in kinds and KIND_ATTEMPTED in kinds
    assert _stdlib_only_ok()
    print(
        "webhook-delivery OK: dispatch, send, retry, verify, pins, audit"
    )


if __name__ == "__main__":
    main()
