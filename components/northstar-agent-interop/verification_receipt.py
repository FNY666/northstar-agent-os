"""Signed, challenge-bound receipts from an evidence verifier.

A receipt is a statement that a verifier checked one exact envelope under one
challenge and observed a result. It is not the evidence, not an authorization,
and not an independent proof that the evidence is true.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from challenge_ledger import ChallengeLedger, LedgerError
from evidence_notarization import (
    EvidenceEnvelope,
    NotarizationError,
    SignatureScheme,
    verify_envelope,
)

SCHEMA = "northstar.verification-receipt.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
_FIELDS = frozenset({
    "schema_version", "envelope_digest", "challenge_id", "verifier_id",
    "evidence_root", "claimed_evidence_state", "unverified",
    "receipt_key_id", "signature",
})
_ALLOWED_EVIDENCE_STATES = frozenset({"verified", "verified-unpinned"})


class ReceiptError(ValueError):
    """Malformed, stale, mismatched, or unverifiable verifier receipt."""


@dataclass(frozen=True)
class VerificationReceipt:
    schema_version: str
    envelope_digest: str
    challenge_id: str
    verifier_id: str
    evidence_root: str
    claimed_evidence_state: str
    unverified: tuple[str, ...]
    receipt_key_id: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "envelope_digest": self.envelope_digest,
            "challenge_id": self.challenge_id,
            "verifier_id": self.verifier_id,
            "evidence_root": self.evidence_root,
            "claimed_evidence_state": self.claimed_evidence_state,
            "unverified": list(self.unverified),
            "receipt_key_id": self.receipt_key_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: Any) -> "VerificationReceipt":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise ReceiptError("receipt fields are invalid")
        if value["schema_version"] != SCHEMA:
            raise ReceiptError("receipt schema is invalid")
        for field in ("envelope_digest", "evidence_root"):
            if not isinstance(value[field], str) or _DIGEST.fullmatch(value[field]) is None:
                raise ReceiptError(f"receipt {field} is invalid")
        for field in ("challenge_id", "verifier_id", "receipt_key_id"):
            if not isinstance(value[field], str) or _ID.fullmatch(value[field]) is None:
                raise ReceiptError(f"receipt {field} is invalid")
        state = value["claimed_evidence_state"]
        if state not in _ALLOWED_EVIDENCE_STATES:
            raise ReceiptError("receipt evidence state is invalid")
        unverified = value["unverified"]
        if not isinstance(unverified, list) or not all(
            isinstance(item, str) and item for item in unverified
        ) or len(set(unverified)) != len(unverified):
            raise ReceiptError("receipt unverified fields are invalid")
        signature = value["signature"]
        if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
            raise ReceiptError("receipt signature is invalid")
        return cls(
            SCHEMA,
            value["envelope_digest"],
            value["challenge_id"],
            value["verifier_id"],
            value["evidence_root"],
            state,
            tuple(unverified),
            value["receipt_key_id"],
            signature,
        )


@dataclass(frozen=True)
class ReceiptVerification:
    state: str
    claimed_evidence_state: str
    reasons: tuple[str, ...] = ()
    unverified: tuple[str, ...] = ()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReceiptError("receipt value is not canonical JSON") from exc


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ReceiptError(f"{field} is invalid")
    return value


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ReceiptError(f"{field} is invalid")
    return value


def _envelope_digest(envelope: EvidenceEnvelope) -> str:
    try:
        return "sha256:" + hashlib.sha256(_canonical(envelope.to_dict())).hexdigest()
    except (AttributeError, TypeError, ValueError) as exc:
        raise ReceiptError("envelope cannot be digested") from exc


def _scheme_call(scheme: SignatureScheme, method: str, *args: Any, **kwargs: Any) -> Any:
    function = getattr(scheme, method, None)
    if not callable(function):
        raise ReceiptError("receipt signature scheme is incomplete")
    try:
        return function(*args, **kwargs)
    except ReceiptError:
        raise
    except Exception as exc:
        raise ReceiptError("receipt signature scheme failed") from exc


def _challenge_id(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 32 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ReceiptError("challenge_id is invalid")
    return value


def issue_verification_receipt(
    *,
    envelope: EvidenceEnvelope,
    ledger: ChallengeLedger,
    challenge_id: str,
    verifier_id: str,
    evidence_anchor: str | None,
    evidence_scheme: SignatureScheme,
    receipt_key_id: str,
    receipt_scheme: SignatureScheme,
    expected_root: str | None = None,
) -> VerificationReceipt:
    if not isinstance(envelope, EvidenceEnvelope):
        raise ReceiptError("envelope is invalid")
    if not isinstance(ledger, ChallengeLedger):
        raise ReceiptError("challenge ledger is invalid")
    challenge_id = _challenge_id(challenge_id)
    verifier_id = _id(verifier_id, "verifier_id")
    receipt_key_id = _id(receipt_key_id, "receipt_key_id")
    try:
        observed = verify_envelope(
            envelope,
            anchor=evidence_anchor,
            scheme=evidence_scheme,
            expected_root=expected_root,
        )
    except NotarizationError as exc:
        raise ReceiptError("evidence envelope verification failed") from exc
    if observed.state not in _ALLOWED_EVIDENCE_STATES:
        raise ReceiptError("evidence result is not receiptable")
    try:
        challenge = ledger.consume(challenge_id, verifier_id=verifier_id)
    except LedgerError as exc:
        raise ReceiptError("challenge was not consumed") from exc
    if challenge.key_id is not None and challenge.key_id != envelope.key_id:
        raise ReceiptError("challenge key does not match evidence envelope")
    unverified = list(observed.unverified)
    unverified.append("receipt-only")
    mode = getattr(receipt_scheme, "mode", "injected-scheme")
    if mode == "same-key":
        unverified.append("same-key")
    unsigned = VerificationReceipt(
        SCHEMA,
        _envelope_digest(envelope),
        challenge.challenge_id,
        verifier_id,
        envelope.disclosure["root_digest"],
        observed.state,
        tuple(dict.fromkeys(unverified)),
        receipt_key_id,
        "",
    )
    signature = _scheme_call(
        receipt_scheme, "sign", _canonical(unsigned.unsigned_dict()),
        key_id=receipt_key_id,
    )
    if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
        raise ReceiptError("receipt signature is invalid")
    return VerificationReceipt(**{**unsigned.__dict__, "signature": signature})


def verify_receipt(
    *,
    receipt: VerificationReceipt,
    envelope: EvidenceEnvelope,
    expected_challenge_id: str,
    expected_verifier_id: str,
    expected_root: str | None = None,
    scheme: SignatureScheme,
) -> ReceiptVerification:
    if not isinstance(receipt, VerificationReceipt):
        raise ReceiptError("receipt is invalid")
    if not isinstance(envelope, EvidenceEnvelope):
        raise ReceiptError("envelope is invalid")
    parsed = VerificationReceipt.from_dict(receipt.to_dict())
    expected_challenge_id = _challenge_id(expected_challenge_id)
    expected_verifier_id = _id(expected_verifier_id, "verifier_id")
    if parsed.challenge_id != expected_challenge_id:
        raise ReceiptError("receipt challenge mismatch")
    if parsed.verifier_id != expected_verifier_id:
        raise ReceiptError("receipt verifier mismatch")
    if expected_root is not None and _digest(expected_root, "expected root") != parsed.evidence_root:
        raise ReceiptError("receipt root mismatch")
    actual_envelope_digest = _envelope_digest(envelope)
    if parsed.envelope_digest != actual_envelope_digest:
        raise ReceiptError("receipt envelope digest mismatch")
    actual_root = envelope.disclosure.get("root_digest")
    if actual_root != parsed.evidence_root:
        raise ReceiptError("receipt evidence root mismatch")
    if not _scheme_call(
        scheme, "verify", _canonical(parsed.unsigned_dict()), parsed.signature,
        key_id=parsed.receipt_key_id,
    ):
        raise ReceiptError("receipt signature mismatch")
    unverified = list(parsed.unverified)
    if expected_root is None:
        unverified.append("root-unpinned")
    mode = getattr(scheme, "mode", "injected-scheme")
    if mode == "same-key":
        unverified.append("same-key")
    return ReceiptVerification(
        "receipt-verified",
        parsed.claimed_evidence_state,
        (),
        tuple(dict.fromkeys(unverified)),
    )


__all__ = [
    "SCHEMA", "ReceiptError", "VerificationReceipt", "ReceiptVerification",
    "issue_verification_receipt", "verify_receipt",
]
