"""Host-owned, non-authorizing admission for autonomous continuation.

An admission states only whether the *declared* continuation predicates agree:
the checkpoint was verified against current host state, it is fresh within the
host policy window, and any required pin is present. It never authorizes
execution, never calls a provider, and never resumes a session.
"""
from __future__ import annotations
import hashlib,json,re
from dataclasses import dataclass
from typing import Any

from autonomy_checkpoint import AutonomyCheckpoint, AutonomyCheckpointError, ContinuationVerdict

POLICY_SCHEMA = "northstar.continuation-policy.v1"
ADMISSION_SCHEMA = "northstar.continuation-admission.v1"
WITNESS_SCHEMA = "northstar.continuation-admission-witness.v1"
ADMISSION_STATES = frozenset({
    "admit-continuation",
    "admit-continuation-unpinned",
    "blocked-continuation-stale",
    "blocked-continuation-age",
    "blocked-continuation-policy",
    "blocked-continuation-objective",
    "unknown",
})
VERDICT_STATES = frozenset({"current", "current-unpinned", "stale", "unknown"})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_POLICY_FIELDS = frozenset({"schema_version", "max_age_seconds", "require_pinned_checkpoint", "require_objective_continuity"})
_ADMISSION_FIELDS = frozenset({
    "schema_version", "state", "reasons", "unresolved", "policy_digest",
    "checkpoint_digest", "age_seconds", "verdict_state", "execution_authorized",
    "admission_digest", "objective_changed_at_sequence",
})
_WITNESS_FIELDS = frozenset({
    "schema_version", "admission_digest", "state", "policy_digest",
    "checkpoint_digest", "observed_at", "witness_digest",
})


class ContinuationAdmissionError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise ContinuationAdmissionError("admission value is not canonical JSON") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _digest_value(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ContinuationAdmissionError(field + " invalid")
    return value


def _tokens(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ContinuationAdmissionError(field + " invalid")
    for item in value:
        if not isinstance(item, str) or not item:
            raise ContinuationAdmissionError(field + " invalid")
    return tuple(value)


@dataclass(frozen=True)
class ContinuationPolicy:
    """Host-declared freshness and pinning requirements for a continuation."""
    max_age_seconds: int
    require_pinned_checkpoint: bool = True
    require_objective_continuity: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.max_age_seconds, int) or isinstance(self.max_age_seconds, bool) or self.max_age_seconds < 0:
            raise ContinuationAdmissionError("max_age_seconds invalid")
        if not isinstance(self.require_pinned_checkpoint, bool):
            raise ContinuationAdmissionError("require_pinned_checkpoint invalid")
        if not isinstance(self.require_objective_continuity, bool):
            raise ContinuationAdmissionError("require_objective_continuity invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": POLICY_SCHEMA,
            "max_age_seconds": self.max_age_seconds,
            "require_pinned_checkpoint": self.require_pinned_checkpoint,
            "require_objective_continuity": self.require_objective_continuity,
        }

    @property
    def policy_digest(self) -> str:
        return _digest(self.to_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "ContinuationPolicy":
        if not isinstance(value, dict) or set(value) != _POLICY_FIELDS or value.get("schema_version") != POLICY_SCHEMA:
            raise ContinuationAdmissionError("policy fields invalid")
        return cls(
            value.get("max_age_seconds"),
            value.get("require_pinned_checkpoint"),
            value.get("require_objective_continuity"),
        )


@dataclass(frozen=True)
class ContinuationAdmission:
    state: str
    reasons: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()
    policy_digest: str | None = None
    checkpoint_digest: str | None = None
    age_seconds: int | None = None
    verdict_state: str | None = None
    execution_authorized: bool = False
    admission_digest: str = ""
    objective_changed_at_sequence: int | None = None

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ADMISSION_SCHEMA,
            "state": self.state,
            "reasons": list(self.reasons),
            "unresolved": list(self.unresolved),
            "policy_digest": self.policy_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "age_seconds": self.age_seconds,
            "verdict_state": self.verdict_state,
            "execution_authorized": self.execution_authorized,
            "objective_changed_at_sequence": self.objective_changed_at_sequence,
        }

    @property
    def computed_digest(self) -> str:
        return _digest(self.unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "admission_digest": self.admission_digest}

    @classmethod
    def from_dict(cls, value: Any) -> "ContinuationAdmission":
        if not isinstance(value, dict) or set(value) != _ADMISSION_FIELDS or value.get("schema_version") != ADMISSION_SCHEMA:
            raise ContinuationAdmissionError("admission fields invalid")
        if value.get("execution_authorized") is not False:
            raise ContinuationAdmissionError("admission cannot authorize execution")
        state = value.get("state")
        if state not in ADMISSION_STATES:
            raise ContinuationAdmissionError("admission state invalid")
        age = value.get("age_seconds")
        if age is not None and (not isinstance(age, int) or isinstance(age, bool)):
            raise ContinuationAdmissionError("age_seconds invalid")
        verdict_state = value.get("verdict_state")
        if verdict_state is not None and verdict_state not in VERDICT_STATES:
            raise ContinuationAdmissionError("verdict_state invalid")
        policy_digest = value.get("policy_digest")
        checkpoint_digest = value.get("checkpoint_digest")
        objective_changed = value.get("objective_changed_at_sequence")
        if objective_changed is not None and (not isinstance(objective_changed, int) or isinstance(objective_changed, bool) or objective_changed < 1):
            raise ContinuationAdmissionError("objective_changed_at_sequence invalid")
        admission = cls(
            state,
            _tokens(value.get("reasons"), "reasons"),
            _tokens(value.get("unresolved"), "unresolved"),
            None if policy_digest is None else _digest_value(policy_digest, "policy_digest"),
            None if checkpoint_digest is None else _digest_value(checkpoint_digest, "checkpoint_digest"),
            age,
            verdict_state,
            False,
            _digest_value(value.get("admission_digest"), "admission_digest"),
            objective_changed,
        )
        if admission.admission_digest != admission.computed_digest:
            raise ContinuationAdmissionError("admission digest mismatch")
        return admission


def _admission(state, reasons, unresolved, policy, checkpoint_digest, age, verdict_state, objective_changed=None):
    draft = ContinuationAdmission(
        state, tuple(reasons), tuple(unresolved), policy.policy_digest,
        checkpoint_digest, age, verdict_state, False, "", objective_changed,
    )
    return ContinuationAdmission(
        draft.state, draft.reasons, draft.unresolved, draft.policy_digest,
        draft.checkpoint_digest, draft.age_seconds, draft.verdict_state,
        False, draft.computed_digest, objective_changed,
    )


def _objective_changed(value: Any) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ContinuationAdmissionError("objective_changed_at_sequence invalid")
    return value


def evaluate_continuation_admission(
    checkpoint: Any, verdict: Any, *, policy: ContinuationPolicy, now: int,
    objective_changed_at_sequence: int | None = None,
    objective_history_unverifiable: bool = False,
) -> ContinuationAdmission:
    """Compose a host policy with a verified continuation; never authorizes execution."""
    if not isinstance(policy, ContinuationPolicy):
        raise ContinuationAdmissionError("policy invalid")
    policy = ContinuationPolicy.from_dict(policy.to_dict())
    if not isinstance(now, int) or isinstance(now, bool):
        raise ContinuationAdmissionError("now invalid")
    if not isinstance(objective_history_unverifiable, bool):
        raise ContinuationAdmissionError("objective_history_unverifiable invalid")
    objective = _objective_changed(objective_changed_at_sequence)
    if not isinstance(verdict, ContinuationVerdict):
        return _admission("unknown", ("verdict_unreadable",), (), policy, None, None, None, objective)
    if verdict.execution_authorized is not False:
        raise ContinuationAdmissionError("verdict cannot authorize execution")
    if verdict.state not in VERDICT_STATES:
        raise ContinuationAdmissionError("verdict state invalid")
    if objective_history_unverifiable:
        return _admission("unknown", ("objective_history_unverifiable",), verdict.unverified, policy, None, None, "unknown", objective)
    if checkpoint is None:
        return _admission("unknown", verdict.reasons or ("checkpoint_unrecorded",), verdict.unverified, policy, None, None, verdict.state, objective)
    try:
        checkpoint = AutonomyCheckpoint.from_dict(checkpoint.to_dict())
    except (AttributeError, AutonomyCheckpointError):
        return _admission("unknown", ("checkpoint_unreadable",), verdict.unverified, policy, None, None, verdict.state, objective)
    age = now - checkpoint.observed_at
    if age < 0:
        return _admission("unknown", ("observation_in_future",), verdict.unverified, policy, checkpoint.checkpoint_digest, None, verdict.state, objective)
    if verdict.state == "unknown":
        return _admission("unknown", verdict.reasons or ("continuation_unverifiable",), verdict.unverified, policy, checkpoint.checkpoint_digest, age, verdict.state, objective)
    if verdict.state == "stale":
        return _admission("blocked-continuation-stale", verdict.reasons, verdict.unverified, policy, checkpoint.checkpoint_digest, age, verdict.state, objective)
    if age > policy.max_age_seconds:
        return _admission("blocked-continuation-age", ("continuation_expired",), verdict.unverified, policy, checkpoint.checkpoint_digest, age, verdict.state, objective)
    if objective is not None and policy.require_objective_continuity:
        return _admission("blocked-continuation-objective", ("continuation_objective_changed",), verdict.unverified, policy, checkpoint.checkpoint_digest, age, verdict.state, objective)
    if verdict.state == "current-unpinned":
        if policy.require_pinned_checkpoint:
            return _admission("blocked-continuation-policy", ("continuation_requires_pinned_checkpoint",), verdict.unverified, policy, checkpoint.checkpoint_digest, age, verdict.state, objective)
        return _admission("admit-continuation-unpinned", verdict.reasons, verdict.unverified, policy, checkpoint.checkpoint_digest, age, verdict.state, objective)
    return _admission("admit-continuation", verdict.reasons, verdict.unverified, policy, checkpoint.checkpoint_digest, age, verdict.state, objective)


@dataclass(frozen=True)
class ContinuationAdmissionWitness:
    """A host-owned record of one observed admission decision."""
    admission_digest: str
    state: str
    policy_digest: str | None
    checkpoint_digest: str | None
    observed_at: int
    witness_digest: str = ""

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": WITNESS_SCHEMA,
            "admission_digest": self.admission_digest,
            "state": self.state,
            "policy_digest": self.policy_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "observed_at": self.observed_at,
        }

    @property
    def computed_digest(self) -> str:
        return _digest(self.unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "witness_digest": self.witness_digest}

    @classmethod
    def from_dict(cls, value: Any) -> "ContinuationAdmissionWitness":
        if not isinstance(value, dict) or set(value) != _WITNESS_FIELDS or value.get("schema_version") != WITNESS_SCHEMA:
            raise ContinuationAdmissionError("witness fields invalid")
        state = value.get("state")
        if state not in ADMISSION_STATES:
            raise ContinuationAdmissionError("witness state invalid")
        observed_at = value.get("observed_at")
        if not isinstance(observed_at, int) or isinstance(observed_at, bool):
            raise ContinuationAdmissionError("observed_at invalid")
        policy_digest = value.get("policy_digest")
        checkpoint_digest = value.get("checkpoint_digest")
        witness = cls(
            _digest_value(value.get("admission_digest"), "admission_digest"),
            state,
            None if policy_digest is None else _digest_value(policy_digest, "policy_digest"),
            None if checkpoint_digest is None else _digest_value(checkpoint_digest, "checkpoint_digest"),
            observed_at,
            _digest_value(value.get("witness_digest"), "witness_digest"),
        )
        if witness.witness_digest != witness.computed_digest:
            raise ContinuationAdmissionError("witness digest mismatch")
        return witness


def capture_admission_witness(admission: Any, *, observed_at: int) -> ContinuationAdmissionWitness:
    """Record an admission so a later check can detect its replacement."""
    if not isinstance(admission, ContinuationAdmission):
        raise ContinuationAdmissionError("admission invalid")
    admission = ContinuationAdmission.from_dict(admission.to_dict())
    if not isinstance(observed_at, int) or isinstance(observed_at, bool):
        raise ContinuationAdmissionError("observed_at invalid")
    draft = ContinuationAdmissionWitness(
        admission.admission_digest, admission.state, admission.policy_digest,
        admission.checkpoint_digest, observed_at,
    )
    return ContinuationAdmissionWitness(
        draft.admission_digest, draft.state, draft.policy_digest,
        draft.checkpoint_digest, draft.observed_at, draft.computed_digest,
    )


def verify_admission_witness(
    witness: Any, admission: Any, *, now: int, expected_witness_digest: str | None = None
) -> ContinuationVerdict:
    """Check a stored witness against a supplied admission; never authorizes execution."""
    if not isinstance(now, int) or isinstance(now, bool):
        raise ContinuationAdmissionError("now invalid")
    if expected_witness_digest is not None:
        _digest_value(expected_witness_digest, "expected_witness_digest")
    try:
        if not isinstance(witness, ContinuationAdmissionWitness):
            witness = ContinuationAdmissionWitness.from_dict(witness)
        else:
            witness = ContinuationAdmissionWitness.from_dict(witness.to_dict())
    except (AttributeError, ContinuationAdmissionError):
        return ContinuationVerdict("unknown", ("witness_unreadable",), (), False)
    try:
        if not isinstance(admission, ContinuationAdmission):
            admission = ContinuationAdmission.from_dict(admission)
        else:
            admission = ContinuationAdmission.from_dict(admission.to_dict())
    except (AttributeError, ContinuationAdmissionError):
        return ContinuationVerdict("unknown", ("admission_unreadable",), (), False)
    if now < witness.observed_at:
        return ContinuationVerdict("unknown", ("observation_in_future",), (), False)
    if witness.admission_digest != admission.admission_digest or witness.state != admission.state:
        return ContinuationVerdict("stale", ("admission_replaced",), (), False)
    if expected_witness_digest is None:
        return ContinuationVerdict("current-unpinned", (), ("witness_digest_unpinned",), False)
    if expected_witness_digest != witness.witness_digest:
        return ContinuationVerdict("stale", ("witness_digest_changed",), (), False)
    return ContinuationVerdict("current", (), (), False)


__all__ = [
    "ADMISSION_SCHEMA", "POLICY_SCHEMA", "WITNESS_SCHEMA", "ADMISSION_STATES",
    "ContinuationAdmissionError", "ContinuationPolicy", "ContinuationAdmission",
    "ContinuationAdmissionWitness", "capture_admission_witness",
    "evaluate_continuation_admission", "verify_admission_witness",
]
