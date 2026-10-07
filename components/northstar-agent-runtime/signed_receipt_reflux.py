"""Signed receipt reflux: closing the approval loop.

Pipeline this closes: decision model -> abstain -> approval SLA queue ->
signed receipt reflux. When an agent abstains and a human (or higher
authority) approves the queued request, a *signed receipt* must flow back
to the decision point. The action executes only when a valid receipt for
that exact request id and action is presented. No receipt, no execution.

Design:

* **SignedReceipt** — frozen dataclass. Carries ``request_id`` (the
  approval-queue request this answers), ``action`` (the exact action
  string approved), ``approver`` (approver identity string), and
  ``approved_at_seq`` (caller-supplied integer sequence number — the
  approval instant on the same logical clock the SLA queue uses).
  The ``signature`` is Ed25519 over the canonical JSON of the receipt
  body, which includes the schema pin.
* **Schema pin inside the signed body** — the signed bytes cover
  ``SCHEMA_PIN``. A receipt minted for one schema version cannot be
  replayed as another; cross-version confusion fails verification.
* **RefluxChannel** — in-memory delivery queue from approver to decision
  point. ``deliver`` enqueues one receipt per request id; a second
  delivery for the same request id is refused (fail closed — a receipt
  authorizes exactly one action, never a standing permission).
  ``collect`` consumes the receipt (pop semantics): once the decision
  point takes it, it is gone, so the same receipt cannot authorize
  twice. ``peek`` inspects without consuming.
* **authorize_action** — the decision-point check. Verifies the
  signature *and* that ``request_id`` and ``action`` match what the
  decision point expects. Signature-valid but wrong-action (or
  wrong-request) receipts are rejected: a receipt is an authorization
  for *this* action, not a capability token.

HONEST SCOPE — read this before deploying:

* This is the receipt *format*, signing/verification, and the in-memory
  delivery channel. It is not a defense against a compromised approver
  key: whoever holds the approver secret can mint receipts. Key
  management, approver authentication, and SLA expiry enforcement live
  outside this module (see the approval SLA queue, which owns the
  deadline).
* The channel is in-memory and single-process. A receipt delivered but
  never collected is lost on restart; durable delivery (fsync'd queue,
  crash recovery) is not provided here — see ``audit_chain``'s
  ``DurableAuditWriter`` for the durability pattern if this channel ever
  needs to survive a crash.
* Verification failures return ``False``; they never raise. Structural
  programming errors (wrong types at issuance) raise ``ValueError``
  loudly at mint time so bugs surface where they are made, not where
  the receipt is checked.
* No wall-clock reads anywhere. ``approved_at_seq`` is a caller-supplied
  integer on the caller's logical clock. Deterministic: same inputs,
  same bytes, same verdict.

All digest/secret comparisons use :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import ed25519


#: Version of the receipt construction described here.
SIGNED_RECEIPT_VERSION = "signed-receipt-reflux.v1"

#: Schema pin, covered by the signature. Binds a receipt to this exact
#: schema so receipts cannot be replayed across schema versions.
SCHEMA_PIN = "northstar.signed-receipt-reflux.v1"

#: Ed25519 secret keys are 32 bytes.
_SECRET_BYTES = 32

#: Receipt body fields covered by the signature, in canonical order.
_SIGNED_FIELDS = ("request_id", "action", "approver", "approved_at_seq", "schema")


class ReceiptError(ValueError):
    """A malformed receipt or a receipt programming error.

    Raised for structural problems at issuance time (bad types, empty
    ids, bad key lengths). Verification *failures* (bad signature,
    tampered fields) return ``False`` instead — the caller is a gate and
    gates fail closed, not loudly.
    """


def _canonical_json(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _receipt_body(request_id: str, action: str, approver: str,
                  approved_at_seq: int) -> Dict[str, Any]:
    """The exact dict covered by the receipt signature."""
    return {
        "request_id": request_id,
        "action": action,
        "approver": approver,
        "approved_at_seq": approved_at_seq,
        "schema": SCHEMA_PIN,
    }


def _check_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ReceiptError(f"{name} must be a non-empty str")
    return value


def _check_seq(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReceiptError(f"{name} must be a non-negative int")
    return value


def _check_secret(secret: Any) -> bytes:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != _SECRET_BYTES:
        raise ReceiptError("approver secret must be 32 bytes")
    return bytes(secret)


def _check_pubkey(pubkey: Any) -> bytes:
    if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != _SECRET_BYTES:
        raise ReceiptError("approver public key must be 32 bytes")
    return bytes(pubkey)


@dataclass(frozen=True)
class SignedReceipt:
    """A signed authorization for one queued approval request.

    ``signature`` is Ed25519 over the canonical JSON of the receipt
    body (request_id, action, approver, approved_at_seq, schema pin).
    """

    request_id: str
    action: str
    approver: str
    approved_at_seq: int
    signature: bytes = field(repr=False)

    def as_dict(self) -> Dict[str, Any]:
        """JSON-safe dict (signature hex-encoded)."""
        return {
            "request_id": self.request_id,
            "action": self.action,
            "approver": self.approver,
            "approved_at_seq": self.approved_at_seq,
            "signature": self.signature.hex(),
            "schema": SCHEMA_PIN,
            "version": SIGNED_RECEIPT_VERSION,
        }


def issue_receipt(request_id: str, action: str, approver: str,
                  approved_at_seq: int, approver_secret: bytes) -> SignedReceipt:
    """Mint and sign a receipt for an approved request.

    Raises :class:`ReceiptError` on malformed inputs. The signature
    covers the schema pin, so the receipt cannot be transplanted to a
    different receipt schema.
    """
    request_id = _check_str("request_id", request_id)
    action = _check_str("action", action)
    approver = _check_str("approver", approver)
    approved_at_seq = _check_seq("approved_at_seq", approved_at_seq)
    secret = _check_secret(approver_secret)
    body = _receipt_body(request_id, action, approver, approved_at_seq)
    sig = ed25519.sign(secret, _canonical_json(body))
    return SignedReceipt(
        request_id=request_id,
        action=action,
        approver=approver,
        approved_at_seq=approved_at_seq,
        signature=sig,
    )


def verify_receipt(receipt: Any, approver_pubkey: bytes) -> bool:
    """Verify a receipt's signature. Fail-closed: never raises.

    Returns ``True`` only if the receipt is a well-formed
    :class:`SignedReceipt` whose signature verifies under
    ``approver_pubkey`` over the exact signed body (including the
    schema pin). Anything else — wrong key, tampered field, malformed
    object, bad key length — returns ``False``.
    """
    try:
        pubkey = _check_pubkey(approver_pubkey)
    except ReceiptError:
        return False
    if not isinstance(receipt, SignedReceipt):
        return False
    try:
        body = _receipt_body(
            _check_str("request_id", receipt.request_id),
            _check_str("action", receipt.action),
            _check_str("approver", receipt.approver),
            _check_seq("approved_at_seq", receipt.approved_at_seq),
        )
        sig = receipt.signature
        if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
            return False
    except ReceiptError:
        return False
    try:
        return bool(ed25519.verify(pubkey, _canonical_json(body), bytes(sig)))
    except Exception:
        return False


class RefluxChannel:
    """In-memory delivery queue: approver -> decision point.

    One receipt per request id. Re-delivery for the same request id is
    refused (a receipt authorizes exactly one action). ``collect``
    consumes the receipt so it cannot authorize twice (replay
    protection at the channel layer; the signature check is the second
    layer at the decision point).
    """

    def __init__(self) -> None:
        self._queue: Dict[str, SignedReceipt] = {}

    def deliver(self, receipt: SignedReceipt) -> bool:
        """Enqueue a receipt. Returns False (refused) if a receipt for
        this request id is already queued. Never raises on a
        well-formed receipt; raises :class:`ReceiptError` on a
        non-receipt."""
        if not isinstance(receipt, SignedReceipt):
            raise ReceiptError("can only deliver a SignedReceipt")
        if receipt.request_id in self._queue:
            return False
        self._queue[receipt.request_id] = receipt
        return True

    def peek(self, request_id: str) -> Optional[SignedReceipt]:
        """Inspect the queued receipt without consuming it."""
        return self._queue.get(request_id)

    def collect(self, request_id: str) -> Optional[SignedReceipt]:
        """Take the receipt for ``request_id``, removing it from the
        queue. Returns None when nothing is queued."""
        return self._queue.pop(request_id, None)

    def pending(self) -> List[str]:
        """Request ids with undelivered-to-decision-point receipts."""
        return sorted(self._queue.keys())

    def __len__(self) -> int:
        return len(self._queue)


def authorize_action(receipt: Any, approver_pubkey: bytes,
                     expected_request_id: str,
                     expected_action: str) -> bool:
    """Decision-point gate: is this action authorized?

    Returns ``True`` only if ``receipt`` is a valid
    :class:`SignedReceipt` under ``approver_pubkey`` **and** its
    ``request_id`` and ``action`` exactly match what the decision point
    expects. A signature-valid receipt for a *different* action or
    request is rejected: receipts authorize one specific action, they
    are not capability tokens. Never raises; fail-closed.
    """
    if not verify_receipt(receipt, approver_pubkey):
        return False
    if not isinstance(expected_request_id, str) or not isinstance(expected_action, str):
        return False
    # Constant-time comparison on the authorization-critical fields.
    req_ok = hmac.compare_digest(receipt.request_id.encode("utf-8"),
                                 expected_request_id.encode("utf-8"))
    act_ok = hmac.compare_digest(receipt.action.encode("utf-8"),
                                 expected_action.encode("utf-8"))
    return bool(req_ok and act_ok)


def receipt_digest(receipt: SignedReceipt) -> str:
    """Stable ``sha256:`` hex digest of a receipt's signed body.

    Useful for audit logging: the digest pins exactly what was
    authorized without storing the signature.
    """
    body = _receipt_body(receipt.request_id, receipt.action,
                         receipt.approver, receipt.approved_at_seq)
    return "sha256:" + hashlib.sha256(_canonical_json(body)).hexdigest()


def main() -> None:
    """Self-check: mint, deliver, collect, authorize."""
    secret = bytes(range(32))
    pubkey = ed25519.public_key(secret)
    receipt = issue_receipt("req-1", "tool:delete:/tmp/x", "human:alice",
                            42, secret)
    assert verify_receipt(receipt, pubkey)
    channel = RefluxChannel()
    assert channel.deliver(receipt) is True
    assert channel.deliver(receipt) is False  # re-delivery refused
    got = channel.collect("req-1")
    assert got is not None
    assert channel.collect("req-1") is None  # consumed
    assert authorize_action(got, pubkey, "req-1", "tool:delete:/tmp/x") is True
    assert authorize_action(got, pubkey, "req-1", "tool:delete:/tmp/y") is False
    print("signed-receipt-reflux OK: issue/verify/deliver/collect/authorize")


if __name__ == "__main__":
    main()
