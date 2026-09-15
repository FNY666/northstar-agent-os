"""Replayable, policy-bound witnesses for evidence admission.

A policy identifier alone cannot explain an admission: the policy body may have
changed while keeping its name.  This module commits the canonical policy body,
its digest, the exact package and claim identity, and the admission result into
a deterministic witness.  A witness remains evidence-policy observation, never
action authorization.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from evidence_admission import (
    AdmissionResult,
    EvidenceAdmissionPolicy,
    PolicyError,
    admit_package,
)
from evidence_notarization import SignatureScheme
from evidence_package import EvidencePackage

SCHEMA = "northstar.admission-witness.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FIELDS = frozenset({
    "schema_version", "policy", "policy_digest", "package_digest",
    "claim_digest", "evidence_root", "claimed_evidence_state",
    "admission_state", "reasons", "unverified", "witness_digest",
})
_ALLOWED_ADMISSION = frozenset({"admissible", "insufficient"})
_ALLOWED_EVIDENCE = frozenset({"verified", "verified-unpinned"})


class WitnessError(ValueError):
    """Malformed, mismatched, stale, or unverifiable admission witness."""


@dataclass(frozen=True)
class AdmissionWitness:
    schema_version: str
    policy: dict[str, Any]
    policy_digest: str
    package_digest: str
    claim_digest: str
    evidence_root: str
    claimed_evidence_state: str
    admission_state: str
    reasons: tuple[str, ...]
    unverified: tuple[str, ...]
    witness_digest: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy": self.policy,
            "policy_digest": self.policy_digest,
            "package_digest": self.package_digest,
            "claim_digest": self.claim_digest,
            "evidence_root": self.evidence_root,
            "claimed_evidence_state": self.claimed_evidence_state,
            "admission_state": self.admission_state,
            "reasons": list(self.reasons),
            "unverified": list(self.unverified),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "witness_digest": self.witness_digest}

    @classmethod
    def from_dict(cls, value: Any) -> "AdmissionWitness":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise WitnessError("admission witness fields are invalid")
        if value["schema_version"] != SCHEMA:
            raise WitnessError("admission witness schema is invalid")
        policy = _policy_wire(value["policy"])
        policy_value = EvidenceAdmissionPolicy.from_dict(policy)
        policy_hash = _digest(value["policy_digest"], "policy_digest")
        if policy_hash != policy_digest(policy_value):
            raise WitnessError("admission witness policy digest mismatch")
        for field in ("package_digest", "claim_digest", "evidence_root", "witness_digest"):
            _digest(value[field], field)
        if value["claimed_evidence_state"] not in _ALLOWED_EVIDENCE:
            raise WitnessError("witness claimed evidence state is invalid")
        if value["admission_state"] not in _ALLOWED_ADMISSION:
            raise WitnessError("witness admission state is invalid")
        reasons = _strings(value["reasons"], "witness reasons")
        unverified = _strings(value["unverified"], "witness unverified")
        witness = cls(
            SCHEMA, policy, policy_hash, value["package_digest"],
            value["claim_digest"], value["evidence_root"],
            value["claimed_evidence_state"], value["admission_state"],
            reasons, unverified, value["witness_digest"],
        )
        if witness.computed_digest != witness.witness_digest:
            raise WitnessError("admission witness digest mismatch")
        return witness

    @property
    def computed_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            b"northstar.admission-witness.v1\0" + _canonical(self.unsigned_dict())
        ).hexdigest()


@dataclass(frozen=True)
class AdmissionWitnessVerdict:
    state: str
    claimed_admission_state: str
    reasons: tuple[str, ...] = ()
    unverified: tuple[str, ...] = ()
    witness_digest: str = ""
    policy_digest: str = ""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WitnessError("witness is not canonical JSON") from exc


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise WitnessError(f"{field} is invalid")
    return value


def _strings(value: Any, field: str) -> tuple[str, ...]:
    if (not isinstance(value, list)
            or not all(isinstance(item, str) and item for item in value)
            or len(set(value)) != len(value)):
        raise WitnessError(f"{field} are invalid")
    return tuple(value)


def _policy_wire(value: Any) -> dict[str, Any]:
    try:
        copied = json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise WitnessError("witness policy is not JSON") from exc
    if not isinstance(copied, dict):
        raise WitnessError("witness policy is invalid")
    return copied


def policy_digest(policy: EvidenceAdmissionPolicy) -> str:
    try:
        parsed = EvidenceAdmissionPolicy.from_dict(policy.to_dict())
    except (AttributeError, PolicyError) as exc:
        raise WitnessError("admission policy is invalid") from exc
    return "sha256:" + hashlib.sha256(
        b"northstar.evidence-admission-policy.v1\0" + _canonical(parsed.to_dict())
    ).hexdigest()


def _make_from_result(policy: EvidenceAdmissionPolicy, result: AdmissionResult) -> AdmissionWitness:
    if result.state not in _ALLOWED_ADMISSION:
        raise WitnessError("unverifiable admission cannot be witnessed")
    unsigned = AdmissionWitness(
        SCHEMA,
        policy.to_dict(),
        policy_digest(policy),
        result.package_digest,
        result.claim_digest,
        result.evidence_root,
        result.claimed_evidence_state,
        result.state,
        tuple(result.reasons),
        tuple(result.unverified),
        "",
    )
    return AdmissionWitness(
        unsigned.schema_version, unsigned.policy, unsigned.policy_digest,
        unsigned.package_digest, unsigned.claim_digest, unsigned.evidence_root,
        unsigned.claimed_evidence_state, unsigned.admission_state,
        unsigned.reasons, unsigned.unverified, unsigned.computed_digest,
    )


def make_admission_witness(
    *,
    package: EvidencePackage,
    policy: EvidenceAdmissionPolicy,
    key_anchor: str | None,
    evidence_scheme: SignatureScheme,
    expected_root: str | None = None,
    expected_package_digest: str | None = None,
    expected_checkpoint_chain_digest: str | None = None,
    receipt_scheme: SignatureScheme | None = None,
    expected_challenge_id: str | None = None,
    expected_verifier_id: str | None = None,
) -> AdmissionWitness:
    try:
        policy = EvidenceAdmissionPolicy.from_dict(policy.to_dict())
    except (AttributeError, PolicyError) as exc:
        raise WitnessError("admission policy is invalid") from exc
    try:
        result = admit_package(
            package=package,
            policy=policy,
            key_anchor=key_anchor,
            evidence_scheme=evidence_scheme,
            expected_root=expected_root,
            expected_package_digest=expected_package_digest,
            expected_checkpoint_chain_digest=expected_checkpoint_chain_digest,
            receipt_scheme=receipt_scheme,
            expected_challenge_id=expected_challenge_id,
            expected_verifier_id=expected_verifier_id,
        )
    except PolicyError as exc:
        raise WitnessError("admission evaluation failed") from exc
    return _make_from_result(policy, result)


def verify_admission_witness(
    *,
    witness: AdmissionWitness,
    package: EvidencePackage,
    expected_witness_digest: str | None = None,
    expected_policy_digest: str | None = None,
    key_anchor: str | None,
    evidence_scheme: SignatureScheme,
    expected_root: str | None = None,
    expected_package_digest: str | None = None,
    expected_checkpoint_chain_digest: str | None = None,
    receipt_scheme: SignatureScheme | None = None,
    expected_challenge_id: str | None = None,
    expected_verifier_id: str | None = None,
) -> AdmissionWitnessVerdict:
    if not isinstance(witness, AdmissionWitness):
        raise WitnessError("admission witness is invalid")
    parsed = AdmissionWitness.from_dict(witness.to_dict())
    if expected_witness_digest is not None:
        if _digest(expected_witness_digest, "expected_witness_digest") != parsed.witness_digest:
            raise WitnessError("external witness digest mismatch")
    if expected_policy_digest is not None:
        if _digest(expected_policy_digest, "expected_policy_digest") != parsed.policy_digest:
            raise WitnessError("external policy digest mismatch")
    policy = EvidenceAdmissionPolicy.from_dict(parsed.policy)
    try:
        replay = admit_package(
            package=package,
            policy=policy,
            key_anchor=key_anchor,
            evidence_scheme=evidence_scheme,
            expected_root=expected_root,
            expected_package_digest=expected_package_digest,
            expected_checkpoint_chain_digest=expected_checkpoint_chain_digest,
            receipt_scheme=receipt_scheme,
            expected_challenge_id=expected_challenge_id,
            expected_verifier_id=expected_verifier_id,
        )
    except PolicyError as exc:
        raise WitnessError("admission replay failed") from exc
    expected_fields = (
        ("state", parsed.admission_state, replay.state),
        ("package_digest", parsed.package_digest, replay.package_digest),
        ("claim_digest", parsed.claim_digest, replay.claim_digest),
        ("evidence_root", parsed.evidence_root, replay.evidence_root),
        ("claimed_evidence_state", parsed.claimed_evidence_state, replay.claimed_evidence_state),
        ("reasons", parsed.reasons, replay.reasons),
        ("unverified", parsed.unverified, replay.unverified),
    )
    for field, expected, actual in expected_fields:
        if expected != actual:
            raise WitnessError("admission witness replay mismatch: " + field)
    unverified = list(replay.unverified)
    if expected_witness_digest is None:
        unverified.append("witness_digest_unpinned")
    if expected_policy_digest is None:
        unverified.append("policy_digest_unpinned")
    critical = {
        "root_unpinned", "root-unpinned", "anchor_unpinned", "key_anchor_unpinned",
        "head_root_unpinned", "chain_digest_unpinned",
        "checkpoint_chain_digest_unpinned", "package_digest_unpinned",
        "witness_digest_unpinned", "policy_digest_unpinned",
    }
    return AdmissionWitnessVerdict(
        "witness-verified-unpinned" if critical.intersection(unverified) else "witness-verified",
        replay.state,
        (),
        tuple(dict.fromkeys(unverified)),
        parsed.witness_digest,
        parsed.policy_digest,
    )


__all__ = [
    "SCHEMA", "WitnessError", "AdmissionWitness", "AdmissionWitnessVerdict",
    "policy_digest", "make_admission_witness", "verify_admission_witness",
]
