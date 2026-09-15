"""Deterministic, conflict-preserving reduction of evidence observations.

Projection gives an agent a compact view of evidence state for a claim.  It
neither resolves contradictory facts nor authorizes an action; ``actionable``
is only an evidence-readiness hint for an owning host policy.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from admission_witness import AdmissionWitness, WitnessError
from evidence_conflict_ledger import ConflictLedgerError, ConflictObservation

SCHEMA = "northstar.evidence-state-projection.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FIELDS = frozenset({
    "schema_version", "claim_digest", "state", "actionable", "witness_digests",
    "package_digests", "conflict_ids", "reasons", "unverified",
})
_STATES = frozenset({"supported", "conflicted", "insufficient", "unverifiable", "unknown"})
_CRITICAL_UNPINNED = frozenset({
    "root_unpinned", "root-unpinned", "anchor_unpinned", "key_anchor_unpinned",
    "head_root_unpinned", "chain_digest_unpinned",
    "checkpoint_chain_digest_unpinned", "package_digest_unpinned",
    "witness_digest_unpinned", "policy_digest_unpinned",
})


class ProjectionError(ValueError):
    """Malformed evidence input or projection state."""


@dataclass(frozen=True)
class ClaimProjection:
    schema_version: str
    claim_digest: str
    state: str
    actionable: bool
    witness_digests: tuple[str, ...]
    package_digests: tuple[str, ...]
    conflict_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    unverified: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "claim_digest": self.claim_digest,
            "state": self.state,
            "actionable": self.actionable,
            "witness_digests": list(self.witness_digests),
            "package_digests": list(self.package_digests),
            "conflict_ids": list(self.conflict_ids),
            "reasons": list(self.reasons),
            "unverified": list(self.unverified),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ClaimProjection":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise ProjectionError("projection fields are invalid")
        if value["schema_version"] != SCHEMA:
            raise ProjectionError("projection schema is invalid")
        claim = _digest(value["claim_digest"], "claim_digest")
        state = value["state"]
        if state not in _STATES:
            raise ProjectionError("projection state is invalid")
        actionable = value["actionable"]
        if not isinstance(actionable, bool) or actionable != (state == "supported"):
            raise ProjectionError("projection actionable flag is invalid")
        witnesses = _digests(value["witness_digests"], "witness_digests")
        packages = _digests(value["package_digests"], "package_digests")
        conflicts = _digests(value["conflict_ids"], "conflict_ids")
        reasons = _strings(value["reasons"], "reasons")
        unverified = _strings(value["unverified"], "unverified")
        if state == "unknown" and witnesses:
            raise ProjectionError("unknown projection cannot contain witnesses")
        if state == "conflicted" and not conflicts:
            raise ProjectionError("conflicted projection requires conflicts")
        return cls(SCHEMA, claim, state, actionable, witnesses, packages, conflicts, reasons, unverified)


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProjectionError(f"{field} is invalid")
    return value


def _digests(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(set(value)) != len(value) or value != sorted(value):
        raise ProjectionError(f"{field} are invalid")
    return tuple(_digest(item, field) for item in value)


def _strings(value: Any, field: str) -> tuple[str, ...]:
    if (not isinstance(value, list)
            or len(set(value)) != len(value)
            or value != sorted(value)
            or not all(isinstance(item, str) and item for item in value)):
        raise ProjectionError(f"{field} are invalid")
    return tuple(value)


def _witness(value: Any) -> AdmissionWitness:
    try:
        return AdmissionWitness.from_dict(value.to_dict())
    except (AttributeError, WitnessError) as exc:
        raise ProjectionError("admission witness is invalid") from exc


def _conflict(value: Any) -> ConflictObservation:
    try:
        return ConflictObservation.from_dict(value.to_dict())
    except (AttributeError, ConflictLedgerError) as exc:
        raise ProjectionError("conflict observation is invalid") from exc


def _projection(
    claim_digest: str,
    state: str,
    witnesses: tuple[AdmissionWitness, ...],
    conflicts: tuple[ConflictObservation, ...],
    reasons: Iterable[str],
    unverified: Iterable[str],
) -> ClaimProjection:
    return ClaimProjection(
        SCHEMA,
        claim_digest,
        state,
        state == "supported",
        tuple(sorted({item.witness_digest for item in witnesses})),
        tuple(sorted({item.package_digest for item in witnesses})),
        tuple(sorted({item.conflict_id for item in conflicts})),
        tuple(sorted(set(reasons))),
        tuple(sorted(set(unverified))),
    )


def project_claim(
    claim_digest: str,
    witnesses: Iterable[AdmissionWitness],
    conflicts: Iterable[ConflictObservation] = (),
) -> ClaimProjection:
    claim_digest = _digest(claim_digest, "claim_digest")
    parsed_witnesses = tuple(_witness(item) for item in witnesses)
    for item in parsed_witnesses:
        if item.claim_digest != claim_digest:
            raise ProjectionError("witness does not match projected claim")
    parsed_conflicts = tuple(_conflict(item) for item in conflicts)
    relevant_conflicts = tuple(item for item in parsed_conflicts if item.claim_digest == claim_digest)
    unverified = [field for item in parsed_witnesses for field in item.unverified]
    if relevant_conflicts:
        reasons = [reason for item in relevant_conflicts for reason in item.reasons]
        return _projection(claim_digest, "conflicted", parsed_witnesses, relevant_conflicts,
                           reasons, unverified)
    if not parsed_witnesses:
        return _projection(claim_digest, "unknown", (), (), ("no_admission_witness",), ())
    if any(item.admission_state == "insufficient" for item in parsed_witnesses):
        return _projection(claim_digest, "insufficient", parsed_witnesses, (),
                           ("admission_insufficient",), unverified)
    if _CRITICAL_UNPINNED.intersection(unverified):
        return _projection(claim_digest, "unverifiable", parsed_witnesses, (),
                           ("unresolved_trust_pins",), unverified)
    return _projection(claim_digest, "supported", parsed_witnesses, (), (), unverified)


def project_state(
    witnesses: Iterable[AdmissionWitness],
    conflicts: Iterable[ConflictObservation] = (),
) -> dict[str, ClaimProjection]:
    parsed_witnesses = tuple(_witness(item) for item in witnesses)
    parsed_conflicts = tuple(_conflict(item) for item in conflicts)
    claims = sorted({item.claim_digest for item in parsed_witnesses} | {item.claim_digest for item in parsed_conflicts})
    return {
        claim: project_claim(
            claim,
            [item for item in parsed_witnesses if item.claim_digest == claim],
            parsed_conflicts,
        )
        for claim in claims
    }


__all__ = [
    "SCHEMA", "ProjectionError", "ClaimProjection", "project_claim", "project_state",
]
