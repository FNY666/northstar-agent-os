"""Deterministic offline composition of the research evidence artifacts.

An EvidencePackage binds an envelope, complete checkpoint witness, key-history
snapshot, and optional verifier receipt.  The package digest protects transport
integrity; it becomes a trust anchor only when a verifier pins it externally.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from checkpoint_chain_witness import (
    CheckpointChainWitness,
    WitnessError,
    verify_witness,
)
from evidence_notarization import (
    EvidenceEnvelope,
    NotarizationError,
    SignatureScheme,
    verify_envelope,
)
from key_history_snapshot import KeyHistorySnapshot, SnapshotError
from key_lifecycle import KeyLifecycleError, KeyRecord, ZERO, _record_digest
from verification_receipt import ReceiptError, VerificationReceipt, verify_receipt

SCHEMA = "northstar.evidence-package.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FIELDS = frozenset({
    "schema_version", "envelope", "checkpoint_witness", "key_snapshot",
    "verifier_receipt", "package_digest",
})


class PackageError(ValueError):
    """Malformed, mismatched, tampered, or insufficiently pinned package."""


@dataclass(frozen=True)
class EvidencePackage:
    schema_version: str
    envelope: dict[str, Any]
    checkpoint_witness: dict[str, Any]
    key_snapshot: dict[str, Any]
    verifier_receipt: dict[str, Any] | None
    package_digest: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "envelope": self.envelope,
            "checkpoint_witness": self.checkpoint_witness,
            "key_snapshot": self.key_snapshot,
            "verifier_receipt": self.verifier_receipt,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "package_digest": self.package_digest}

    @classmethod
    def from_dict(cls, value: Any) -> "EvidencePackage":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise PackageError("package fields are invalid")
        if value["schema_version"] != SCHEMA:
            raise PackageError("package schema is invalid")
        envelope = _envelope(value["envelope"])
        witness = _witness(value["checkpoint_witness"])
        snapshot = _snapshot(value["key_snapshot"])
        receipt = _receipt(value["verifier_receipt"])
        digest = _digest(value["package_digest"], "package_digest")
        package = cls(
            SCHEMA,
            envelope.to_dict(),
            witness.to_dict(),
            snapshot.to_dict(),
            receipt.to_dict() if receipt else None,
            digest,
        )
        if package.computed_digest != digest:
            raise PackageError("package digest mismatch")
        _validate_bindings(envelope, witness, snapshot, receipt)
        return package

    @property
    def computed_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            b"northstar.evidence-package.v1\0" + _canonical(self.unsigned_dict())
        ).hexdigest()


@dataclass(frozen=True)
class PackageVerdict:
    state: str
    claimed_evidence_state: str
    reasons: tuple[str, ...] = ()
    unverified: tuple[str, ...] = ()
    package_digest: str = ""
    receipt_state: str | None = None


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PackageError("package is not canonical JSON") from exc


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise PackageError(f"{field} is invalid")
    return value


def _envelope(value: Any) -> EvidenceEnvelope:
    try:
        return EvidenceEnvelope.from_dict(value)
    except (NotarizationError, TypeError, KeyError) as exc:
        raise PackageError("package envelope is invalid") from exc


def _witness(value: Any) -> CheckpointChainWitness:
    try:
        return CheckpointChainWitness.from_dict(value)
    except (WitnessError, TypeError, KeyError) as exc:
        raise PackageError("package checkpoint witness is invalid") from exc


def _snapshot(value: Any) -> KeyHistorySnapshot:
    try:
        return KeyHistorySnapshot.from_dict(value)
    except (SnapshotError, TypeError, KeyError) as exc:
        raise PackageError("package key snapshot is invalid") from exc


def _receipt(value: Any) -> VerificationReceipt | None:
    if value is None:
        return None
    try:
        return VerificationReceipt.from_dict(value)
    except (ReceiptError, TypeError, KeyError) as exc:
        raise PackageError("package verifier receipt is invalid") from exc


def _verify_snapshot_prefix(records: tuple[dict[str, Any], ...], snapshot: KeyHistorySnapshot,
                            key_anchor: str | None = None) -> tuple[str, ...]:
    if snapshot.revision > len(records):
        raise PackageError("key snapshot is beyond embedded history")
    previous = ZERO
    parsed = []
    for raw in records[:snapshot.revision]:
        try:
            record = KeyRecord.from_dict(raw)
        except KeyLifecycleError as exc:
            raise PackageError("embedded key history record is invalid") from exc
        if record.revision != len(parsed) + 1 or record.previous_digest != previous:
            raise PackageError("embedded key history chain is broken")
        if _record_digest(record.revision, record.key_id, record.material_digest,
                          record.action, record.previous_digest) != record.record_digest:
            raise PackageError("embedded key history digest mismatch")
        parsed.append(record)
        previous = record.record_digest
    if not parsed:
        raise PackageError("embedded key history is empty")
    if parsed[0].record_digest != snapshot.anchor_digest:
        raise PackageError("key snapshot anchor does not bind embedded history")
    if parsed[-1].record_digest != snapshot.head_digest:
        raise PackageError("key snapshot head does not bind embedded history")
    if key_anchor is None:
        return ("key_anchor_unpinned",)
    if _digest(key_anchor, "key_anchor") != snapshot.anchor_digest:
        raise PackageError("external key anchor mismatch")
    return ()


def _validate_bindings(envelope: EvidenceEnvelope, witness: CheckpointChainWitness,
                       snapshot: KeyHistorySnapshot, receipt: VerificationReceipt | None) -> None:
    root = envelope.disclosure["root_digest"]
    if envelope.checkpoint_head.get("current_root") != root:
        raise PackageError("envelope checkpoint head does not bind disclosure root")
    if witness.head_root != root:
        raise PackageError("checkpoint witness head does not bind envelope root")
    _verify_snapshot_prefix(envelope.key_history, snapshot, snapshot.anchor_digest)
    if receipt is not None:
        envelope_digest = "sha256:" + hashlib.sha256(_canonical(envelope.to_dict())).hexdigest()
        if receipt.envelope_digest != envelope_digest:
            raise PackageError("receipt does not bind package envelope")
        if receipt.evidence_root != root:
            raise PackageError("receipt does not bind package evidence root")


def build_package(envelope: EvidenceEnvelope, checkpoint_witness: CheckpointChainWitness,
                  key_snapshot: KeyHistorySnapshot,
                  *, verifier_receipt: VerificationReceipt | None = None) -> EvidencePackage:
    if not isinstance(envelope, EvidenceEnvelope):
        raise PackageError("envelope is invalid")
    if not isinstance(checkpoint_witness, CheckpointChainWitness):
        raise PackageError("checkpoint witness is invalid")
    if not isinstance(key_snapshot, KeyHistorySnapshot):
        raise PackageError("key snapshot is invalid")
    if verifier_receipt is not None and not isinstance(verifier_receipt, VerificationReceipt):
        raise PackageError("verifier receipt is invalid")
    _validate_bindings(envelope, checkpoint_witness, key_snapshot, verifier_receipt)
    unsigned = EvidencePackage(
        SCHEMA,
        envelope.to_dict(),
        checkpoint_witness.to_dict(),
        key_snapshot.to_dict(),
        verifier_receipt.to_dict() if verifier_receipt else None,
        "",
    )
    return EvidencePackage(
        SCHEMA, unsigned.envelope, unsigned.checkpoint_witness, unsigned.key_snapshot,
        unsigned.verifier_receipt, unsigned.computed_digest,
    )


def verify_package(
    package: EvidencePackage,
    *,
    key_anchor: str | None,
    evidence_scheme: SignatureScheme,
    expected_root: str | None = None,
    expected_package_digest: str | None = None,
    expected_checkpoint_chain_digest: str | None = None,
    receipt_scheme: SignatureScheme | None = None,
    expected_challenge_id: str | None = None,
    expected_verifier_id: str | None = None,
) -> PackageVerdict:
    if not isinstance(package, EvidencePackage):
        raise PackageError("package is invalid")
    parsed = EvidencePackage.from_dict(package.to_dict())
    if expected_package_digest is not None:
        if _digest(expected_package_digest, "expected_package_digest") != parsed.package_digest:
            raise PackageError("external package digest mismatch")
    envelope = _envelope(parsed.envelope)
    witness = _witness(parsed.checkpoint_witness)
    snapshot = _snapshot(parsed.key_snapshot)
    receipt = _receipt(parsed.verifier_receipt)
    try:
        envelope_verdict = verify_envelope(
            envelope, anchor=key_anchor, scheme=evidence_scheme,
            expected_root=expected_root,
        )
    except NotarizationError as exc:
        raise PackageError("package envelope verification failed") from exc
    if envelope_verdict.state not in {"verified", "verified-unpinned"}:
        raise PackageError("package envelope has no receiptable state")
    try:
        witness_verdict = verify_witness(
            witness,
            expected_head_root=envelope.disclosure["root_digest"],
            expected_chain_digest=expected_checkpoint_chain_digest,
        )
    except WitnessError as exc:
        raise PackageError("package checkpoint witness verification failed") from exc
    snapshot_unverified = _verify_snapshot_prefix(
        envelope.key_history, snapshot, key_anchor,
    )
    receipt_state = None
    receipt_unverified: tuple[str, ...] = ()
    if receipt is not None:
        if receipt_scheme is None or expected_challenge_id is None or expected_verifier_id is None:
            raise PackageError("verifier receipt context is required")
        try:
            receipt_verdict = verify_receipt(
                receipt=receipt,
                envelope=envelope,
                expected_challenge_id=expected_challenge_id,
                expected_verifier_id=expected_verifier_id,
                expected_root=expected_root,
                scheme=receipt_scheme,
            )
        except ReceiptError as exc:
            raise PackageError("package verifier receipt verification failed") from exc
        receipt_state = receipt_verdict.state
        receipt_unverified = receipt_verdict.unverified
    unverified = list(envelope_verdict.unverified)
    unverified.extend(
        "checkpoint_chain_digest_unpinned" if item == "chain_digest_unpinned" else item
        for item in witness_verdict.unverified
    )
    unverified.extend(snapshot_unverified)
    unverified.extend(receipt_unverified)
    if expected_package_digest is None:
        unverified.append("package_digest_unpinned")
    critical = {
        "root_unpinned", "anchor_unpinned", "head_root_unpinned",
        "chain_digest_unpinned", "key_anchor_unpinned", "root-unpinned",
        "package_digest_unpinned",
    }
    state = "verified-unpinned" if critical.intersection(unverified) else "verified"
    return PackageVerdict(
        state,
        envelope_verdict.state,
        (),
        tuple(dict.fromkeys(unverified)),
        parsed.package_digest,
        receipt_state,
    )


__all__ = [
    "SCHEMA", "PackageError", "EvidencePackage", "PackageVerdict",
    "build_package", "verify_package",
]
