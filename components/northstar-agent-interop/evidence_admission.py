"""Policy-driven admission for portable evidence packages.

Admission decides whether evidence meets a declared *evidence* policy. It does
not authorize an action, resolve a factual dispute, or select a winner between
conflicting evidence packages.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from evidence_notarization import SignatureScheme
from evidence_package import EvidencePackage, PackageError, verify_package

SCHEMA = "northstar.evidence-admission-policy.v1"
_POLICY_FIELDS = frozenset({
    "schema_version", "policy_id", "require_external_root",
    "require_external_package_digest", "require_external_checkpoint_chain_digest",
    "require_key_anchor", "require_receipt", "allow_unpinned",
    "forbidden_unverified",
})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class PolicyError(ValueError):
    """Malformed policy, package admission context, or admission comparison."""


@dataclass(frozen=True)
class EvidenceAdmissionPolicy:
    schema_version: str
    policy_id: str
    require_external_root: bool
    require_external_package_digest: bool
    require_external_checkpoint_chain_digest: bool
    require_key_anchor: bool
    require_receipt: bool
    allow_unpinned: bool
    forbidden_unverified: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "require_external_root": self.require_external_root,
            "require_external_package_digest": self.require_external_package_digest,
            "require_external_checkpoint_chain_digest": self.require_external_checkpoint_chain_digest,
            "require_key_anchor": self.require_key_anchor,
            "require_receipt": self.require_receipt,
            "allow_unpinned": self.allow_unpinned,
            "forbidden_unverified": list(self.forbidden_unverified),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "EvidenceAdmissionPolicy":
        if not isinstance(value, dict) or set(value) != _POLICY_FIELDS:
            raise PolicyError("admission policy fields are invalid")
        if value["schema_version"] != SCHEMA:
            raise PolicyError("admission policy schema is invalid")
        policy_id = _id(value["policy_id"], "policy_id")
        flags = (
            "require_external_root", "require_external_package_digest",
            "require_external_checkpoint_chain_digest", "require_key_anchor",
            "require_receipt", "allow_unpinned",
        )
        if any(not isinstance(value[field], bool) for field in flags):
            raise PolicyError("admission policy flags are invalid")
        forbidden = value["forbidden_unverified"]
        if (not isinstance(forbidden, list)
                or not all(isinstance(item, str) and item for item in forbidden)
                or len(set(forbidden)) != len(forbidden)):
            raise PolicyError("forbidden unverified fields are invalid")
        return cls(
            SCHEMA, policy_id,
            *(value[field] for field in flags),
            tuple(forbidden),
        )


@dataclass(frozen=True)
class AdmissionResult:
    state: str
    policy_id: str
    claim_digest: str
    evidence_root: str
    claimed_evidence_state: str
    package_digest: str
    reasons: tuple[str, ...]
    unverified: tuple[str, ...]


@dataclass(frozen=True)
class ConflictComparison:
    state: str
    claim_digest: str
    left_package_digest: str
    right_package_digest: str
    reasons: tuple[str, ...] = ()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PolicyError("claim is not canonical JSON") from exc


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise PolicyError(f"{field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise PolicyError(f"{field} is invalid")
    return value


def _claim_digest(package: EvidencePackage) -> str:
    try:
        subject = package.envelope["subject"]
        fields = {
            "route_id", "target_agent_id", "provider", "payload_digest",
            "decision_fingerprint", "event_digest",
        }
        if not isinstance(subject, dict) or not fields.issubset(subject):
            raise PolicyError("envelope subject cannot identify a claim")
        claim = {field: subject[field] for field in sorted(fields)}
        _id(claim["route_id"], "route_id")
        _id(claim["target_agent_id"], "target_agent_id")
        _id(claim["provider"], "provider")
        for field in ("payload_digest", "decision_fingerprint", "event_digest"):
            _digest(claim[field], field)
    except (KeyError, TypeError) as exc:
        raise PolicyError("envelope subject cannot identify a claim") from exc
    return "sha256:" + hashlib.sha256(
        b"northstar.evidence-admission-claim.v1\0" + _canonical(claim)
    ).hexdigest()


def _unverifiable(policy: EvidenceAdmissionPolicy, reason: str) -> AdmissionResult:
    return AdmissionResult(
        "unverifiable", policy.policy_id, "", "", "", "", (reason,), (),
    )


def admit_package(
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
) -> AdmissionResult:
    try:
        policy = EvidenceAdmissionPolicy.from_dict(policy.to_dict())
    except AttributeError as exc:
        raise PolicyError("admission policy is invalid") from exc
    if not isinstance(package, EvidencePackage):
        raise PolicyError("evidence package is invalid")
    try:
        package_verdict = verify_package(
            package,
            key_anchor=key_anchor,
            evidence_scheme=evidence_scheme,
            expected_root=expected_root,
            expected_package_digest=expected_package_digest,
            expected_checkpoint_chain_digest=expected_checkpoint_chain_digest,
            receipt_scheme=receipt_scheme,
            expected_challenge_id=expected_challenge_id,
            expected_verifier_id=expected_verifier_id,
        )
        claim = _claim_digest(package)
    except (PackageError, PolicyError, ValueError):
        return _unverifiable(policy, "package_verification_failed")
    reasons: list[str] = []
    if policy.require_external_root and expected_root is None:
        reasons.append("external_root_required")
    if policy.require_external_package_digest and expected_package_digest is None:
        reasons.append("external_package_digest_required")
    if (policy.require_external_checkpoint_chain_digest
            and expected_checkpoint_chain_digest is None):
        reasons.append("external_checkpoint_chain_digest_required")
    if policy.require_key_anchor and key_anchor is None:
        reasons.append("key_anchor_required")
    if policy.require_receipt and package.verifier_receipt is None:
        reasons.append("verifier_receipt_required")
    critical_unpinned = {
        "root_unpinned", "root-unpinned", "anchor_unpinned", "key_anchor_unpinned",
        "head_root_unpinned", "chain_digest_unpinned",
        "checkpoint_chain_digest_unpinned", "package_digest_unpinned",
    }
    if not policy.allow_unpinned and critical_unpinned.intersection(package_verdict.unverified):
        reasons.append("unresolved_external_pins")
    for field in policy.forbidden_unverified:
        if field in package_verdict.unverified:
            reasons.append("forbidden_unverified:" + field)
    return AdmissionResult(
        "insufficient" if reasons else "admissible",
        policy.policy_id,
        claim,
        package.envelope["disclosure"]["root_digest"],
        package_verdict.claimed_evidence_state,
        package.package_digest,
        tuple(dict.fromkeys(reasons)),
        package_verdict.unverified,
    )


def _validate_admission(value: Any) -> AdmissionResult:
    if not isinstance(value, AdmissionResult):
        raise PolicyError("admission result is invalid")
    if value.state not in {"admissible", "insufficient", "unverifiable"}:
        raise PolicyError("admission state is invalid")
    _id(value.policy_id, "policy_id")
    for field in ("claim_digest", "evidence_root", "package_digest"):
        _digest(getattr(value, field), field)
    if value.claimed_evidence_state not in {"verified", "verified-unpinned"}:
        raise PolicyError("claimed evidence state is invalid")
    if not all(isinstance(item, str) and item for item in value.reasons + value.unverified):
        raise PolicyError("admission reasons are invalid")
    return value


def compare_admissions(left: AdmissionResult, right: AdmissionResult) -> ConflictComparison:
    left = _validate_admission(left)
    right = _validate_admission(right)
    if left.claim_digest != right.claim_digest:
        return ConflictComparison(
            "incomparable", "", left.package_digest, right.package_digest,
            ("claim_digest_mismatch",),
        )
    reasons: list[str] = []
    if left.evidence_root != right.evidence_root:
        reasons.append("evidence_root_mismatch")
    if left.claimed_evidence_state != right.claimed_evidence_state:
        reasons.append("claimed_evidence_state_mismatch")
    return ConflictComparison(
        "conflicting" if reasons else "consistent",
        left.claim_digest,
        left.package_digest,
        right.package_digest,
        tuple(reasons),
    )


__all__ = [
    "SCHEMA", "PolicyError", "EvidenceAdmissionPolicy", "AdmissionResult",
    "ConflictComparison", "admit_package", "compare_admissions",
]
