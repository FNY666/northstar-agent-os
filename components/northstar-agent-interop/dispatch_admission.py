"""Compose evidence readiness and route liveness into one non-authorizing verdict."""
from __future__ import annotations
import hashlib, json, re
from dataclasses import dataclass
from typing import Any

from evidence_readiness_preflight import EvidenceReadinessPreflight, PreflightError
from route_liveness import RouteLivenessVerdict

SCHEMA = "northstar.dispatch-admission.v1"
STATES = ("admit", "admit-unpinned", "blocked-evidence", "blocked-route", "blocked-both", "unknown")
EVIDENCE_READY = ("preflight-ready",)
EVIDENCE_UNPINNED = ("preflight-unpinned",)
ROUTE_OPEN = ("dispatchable", "retryable")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FIELDS = frozenset({
    "schema_version", "plan_id", "route_id", "state", "evidence_state",
    "route_state", "unverified", "reasons", "execution_authorized",
    "admission_digest",
})


class DispatchAdmissionError(ValueError):
    pass


@dataclass(frozen=True)
class DispatchAdmission:
    schema_version: str
    plan_id: str
    route_id: str
    state: str
    evidence_state: str
    route_state: str
    unverified: tuple[str, ...]
    reasons: tuple[str, ...]
    execution_authorized: bool
    admission_digest: str

    def unsigned_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "route_id": self.route_id,
            "state": self.state,
            "evidence_state": self.evidence_state,
            "route_state": self.route_state,
            "unverified": list(self.unverified),
            "reasons": list(self.reasons),
            "execution_authorized": self.execution_authorized,
        }

    def to_dict(self) -> dict:
        return {**self.unsigned_dict(), "admission_digest": self.admission_digest}

    @property
    def computed_digest(self) -> str:
        return _hash(b"northstar.dispatch-admission.v1\0", self.unsigned_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "DispatchAdmission":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise DispatchAdmissionError("admission fields invalid")
        if value["schema_version"] != SCHEMA:
            raise DispatchAdmissionError("admission schema invalid")
        if value["state"] not in STATES:
            raise DispatchAdmissionError("admission state invalid")
        if not isinstance(value["execution_authorized"], bool) or value["execution_authorized"]:
            raise DispatchAdmissionError("admission cannot authorize execution")
        digest = value["admission_digest"]
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise DispatchAdmissionError("admission digest invalid")
        result = cls(
            SCHEMA, _label(value["plan_id"], "plan_id"), _label(value["route_id"], "route_id"),
            value["state"], value["evidence_state"], value["route_state"],
            tuple(value["unverified"]), tuple(value["reasons"]), False, digest,
        )
        if result.computed_digest != digest:
            raise DispatchAdmissionError("admission digest mismatch")
        return result


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    except (TypeError, ValueError) as exc:
        raise DispatchAdmissionError("admission is not canonical JSON") from exc


def _hash(prefix: bytes, value: Any) -> str:
    return "sha256:" + hashlib.sha256(prefix + _canonical(value)).hexdigest()


def _label(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise DispatchAdmissionError(f"{field} invalid")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise DispatchAdmissionError(f"{field} invalid")
    return value


def evaluate_dispatch_admission(
    preflight: Any, liveness: Any, *, plan_id: str
) -> DispatchAdmission:
    """Combine evidence readiness with route liveness; never authorises a dispatch."""
    if not isinstance(preflight, EvidenceReadinessPreflight):
        raise DispatchAdmissionError("preflight invalid")
    if not isinstance(liveness, RouteLivenessVerdict):
        raise DispatchAdmissionError("liveness invalid")
    plan = _label(plan_id, "plan_id")
    try:
        preflight = EvidenceReadinessPreflight.from_dict(preflight.to_dict())
    except PreflightError as exc:
        raise DispatchAdmissionError("preflight invalid") from exc
    evidence_state = preflight.state
    route_state = liveness.state
    unverified = tuple(sorted(set(preflight.unverified) | set(liveness.unverified)))
    evidence_open = evidence_state in EVIDENCE_READY
    evidence_unpinned = evidence_state in EVIDENCE_UNPINNED
    route_open = route_state in ROUTE_OPEN
    if evidence_state == "preflight-unknown" or route_state == "unknown":
        state = "unknown"
    elif not route_open and not (evidence_open or evidence_unpinned):
        state = "blocked-both"
    elif not route_open:
        state = "blocked-route"
    elif not (evidence_open or evidence_unpinned):
        state = "blocked-evidence"
    elif evidence_open and not unverified:
        state = "admit"
    else:
        state = "admit-unpinned"
    reasons = (
        "evidence:" + evidence_state,
        "route:" + route_state,
        "admission:" + state,
    )
    draft = DispatchAdmission(
        SCHEMA, plan, liveness.route_id, state, evidence_state, route_state,
        unverified, reasons, False, "",
    )
    return DispatchAdmission(
        draft.schema_version, draft.plan_id, draft.route_id, draft.state,
        draft.evidence_state, draft.route_state, draft.unverified, draft.reasons,
        False, draft.computed_digest,
    )


__all__ = [
    "SCHEMA", "STATES", "DispatchAdmission", "DispatchAdmissionError",
    "evaluate_dispatch_admission",
]
