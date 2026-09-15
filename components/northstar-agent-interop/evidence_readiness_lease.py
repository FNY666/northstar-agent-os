"""Freshness leases for fully pinned ready evidence decisions.

A readiness lease is not permission to run a plan.  It binds one exact ready
PlanEvidenceDecision to injected time so a caller can detect expiry or source
drift before treating that previous evidence conclusion as current.
"""
from __future__ import annotations
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from evidence_state_projection import ClaimProjection, ProjectionError
from plan_evidence_decision import (
    EvidencePlanManifest,
    PlanDecisionError,
    PlanEvidenceDecision,
    verify_plan_evidence_decision,
)

SCHEMA = "northstar.evidence-readiness-lease.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_FIELDS = frozenset({
    "schema_version", "plan_id", "decision_digest", "manifest_digest",
    "gate_digest", "issued_at", "expires_at", "execution_authorized",
    "lease_digest",
})


class LeaseError(ValueError):
    """Malformed, stale, drifted, or insufficiently pinned readiness lease."""


@dataclass(frozen=True)
class EvidenceReadinessLease:
    schema_version: str
    plan_id: str
    decision_digest: str
    manifest_digest: str
    gate_digest: str
    issued_at: int
    expires_at: int
    execution_authorized: bool
    lease_digest: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "decision_digest": self.decision_digest,
            "manifest_digest": self.manifest_digest,
            "gate_digest": self.gate_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "execution_authorized": self.execution_authorized,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "lease_digest": self.lease_digest}

    @property
    def computed_digest(self) -> str:
        return _hash(b"northstar.evidence-readiness-lease.v1\0", self.unsigned_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "EvidenceReadinessLease":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise LeaseError("lease fields are invalid")
        if value["schema_version"] != SCHEMA:
            raise LeaseError("lease schema is invalid")
        _id(value["plan_id"], "plan_id")
        for field in ("decision_digest", "manifest_digest", "gate_digest", "lease_digest"):
            _digest(value[field], field)
        issued = _time(value["issued_at"], "issued_at")
        expires = _time(value["expires_at"], "expires_at")
        if expires <= issued:
            raise LeaseError("lease expiry is invalid")
        if not isinstance(value["execution_authorized"], bool) or value["execution_authorized"]:
            raise LeaseError("lease cannot authorize execution")
        lease = cls(
            SCHEMA, value["plan_id"], value["decision_digest"],
            value["manifest_digest"], value["gate_digest"], issued, expires,
            False, value["lease_digest"],
        )
        if lease.computed_digest != lease.lease_digest:
            raise LeaseError("lease digest mismatch")
        return lease


@dataclass(frozen=True)
class LeaseVerdict:
    state: str
    claimed_decision_state: str
    reasons: tuple[str, ...] = ()
    unverified: tuple[str, ...] = ()
    execution_authorized: bool = False
    lease_digest: str = ""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LeaseError("lease is not canonical JSON") from exc


def _hash(prefix: bytes, value: Any) -> str:
    return "sha256:" + hashlib.sha256(prefix + _canonical(value)).hexdigest()


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LeaseError(f"{field} is invalid")
    return value


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise LeaseError(f"{field} is invalid")
    return value


def _time(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise LeaseError(f"{field} is invalid")
    return value


def _manifest(value: Any) -> EvidencePlanManifest:
    try:
        return EvidencePlanManifest.from_dict(value.to_dict())
    except (AttributeError, PlanDecisionError) as exc:
        raise LeaseError("manifest is invalid") from exc


def _decision(value: Any) -> PlanEvidenceDecision:
    try:
        return PlanEvidenceDecision.from_dict(value.to_dict())
    except (AttributeError, PlanDecisionError) as exc:
        raise LeaseError("plan evidence decision is invalid") from exc


def _projections(values: Any) -> Mapping[str, ClaimProjection]:
    if not isinstance(values, Mapping):
        raise LeaseError("projections are invalid")
    parsed: dict[str, ClaimProjection] = {}
    for claim, value in values.items():
        _digest(claim, "projection claim")
        try:
            projection = ClaimProjection.from_dict(value.to_dict())
        except (AttributeError, ProjectionError) as exc:
            raise LeaseError("projection is invalid") from exc
        if projection.claim_digest != claim:
            raise LeaseError("projection mapping mismatch")
        parsed[claim] = projection
    return parsed


def _plan_id(manifest: EvidencePlanManifest) -> str:
    return "plan-evidence:" + manifest.manifest_digest[7:23]


def _verify_ready_source(
    decision: PlanEvidenceDecision,
    manifest: EvidencePlanManifest,
    projections: Mapping[str, ClaimProjection],
    *,
    expected_decision_digest: str | None,
    expected_manifest_digest: str | None,
    expected_gate_digest: str | None,
):
    if (expected_decision_digest is None or expected_manifest_digest is None
            or expected_gate_digest is None):
        raise LeaseError("fully pinned decision sources are required")
    try:
        verdict = verify_plan_evidence_decision(
            decision,
            manifest=manifest,
            projections=projections,
            expected_decision_digest=expected_decision_digest,
            expected_manifest_digest=expected_manifest_digest,
            expected_gate_digest=expected_gate_digest,
        )
    except PlanDecisionError as exc:
        raise LeaseError("plan evidence decision verification failed") from exc
    if verdict.state != "decision-verified" or verdict.claimed_state != "ready":
        raise LeaseError("only fully pinned ready evidence decisions can issue leases")
    return verdict


def issue_readiness_lease(
    decision: PlanEvidenceDecision,
    manifest: EvidencePlanManifest,
    projections: Mapping[str, ClaimProjection],
    *,
    now: int,
    ttl: int,
    expected_decision_digest: str | None,
    expected_manifest_digest: str | None,
    expected_gate_digest: str | None,
) -> EvidenceReadinessLease:
    now = _time(now, "now")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        raise LeaseError("ttl is invalid")
    decision = _decision(decision)
    manifest = _manifest(manifest)
    projections = _projections(projections)
    _verify_ready_source(
        decision, manifest, projections,
        expected_decision_digest=expected_decision_digest,
        expected_manifest_digest=expected_manifest_digest,
        expected_gate_digest=expected_gate_digest,
    )
    if decision.plan_id if hasattr(decision, "plan_id") else False:
        raise LeaseError("unexpected decision plan id")
    lease = EvidenceReadinessLease(
        SCHEMA, _plan_id(manifest), decision.decision_digest,
        manifest.manifest_digest, decision.gate["gate_digest"],
        now, now + ttl, False, "",
    )
    return EvidenceReadinessLease(
        lease.schema_version, lease.plan_id, lease.decision_digest,
        lease.manifest_digest, lease.gate_digest, lease.issued_at,
        lease.expires_at, False, lease.computed_digest,
    )


def verify_readiness_lease(
    lease: EvidenceReadinessLease,
    decision: PlanEvidenceDecision,
    manifest: EvidencePlanManifest,
    projections: Mapping[str, ClaimProjection],
    *,
    now: int,
    expected_lease_digest: str | None = None,
    expected_decision_digest: str | None,
    expected_manifest_digest: str | None,
    expected_gate_digest: str | None,
) -> LeaseVerdict:
    if not isinstance(lease, EvidenceReadinessLease):
        raise LeaseError("lease is invalid")
    parsed = EvidenceReadinessLease.from_dict(lease.to_dict())
    now = _time(now, "now")
    decision = _decision(decision)
    manifest = _manifest(manifest)
    projections = _projections(projections)
    if parsed.plan_id != _plan_id(manifest):
        raise LeaseError("lease plan id mismatch")
    if parsed.decision_digest != decision.decision_digest:
        raise LeaseError("lease decision digest mismatch")
    if parsed.manifest_digest != manifest.manifest_digest:
        raise LeaseError("lease manifest digest mismatch")
    if parsed.gate_digest != decision.gate["gate_digest"]:
        raise LeaseError("lease gate digest mismatch")
    _verify_ready_source(
        decision, manifest, projections,
        expected_decision_digest=expected_decision_digest,
        expected_manifest_digest=expected_manifest_digest,
        expected_gate_digest=expected_gate_digest,
    )
    if expected_lease_digest is not None:
        if _digest(expected_lease_digest, "expected_lease_digest") != parsed.lease_digest:
            raise LeaseError("external lease digest mismatch")
    unresolved = [
        field for projection in projections.values() for field in projection.unverified
    ]
    if now > parsed.expires_at:
        return LeaseVerdict(
            "lease-expired", "ready", ("lease_expired",),
            tuple(sorted(set(unresolved))), False, parsed.lease_digest,
        )
    if expected_lease_digest is None:
        unresolved.append("lease_digest_unpinned")
    return LeaseVerdict(
        "lease-valid" if expected_lease_digest is not None else "lease-valid-unpinned",
        "ready", (), tuple(sorted(set(unresolved))), False, parsed.lease_digest,
    )


__all__ = [
    "SCHEMA", "LeaseError", "EvidenceReadinessLease", "LeaseVerdict",
    "issue_readiness_lease", "verify_readiness_lease",
]
