"""PowerSeeking: instrumental-goal detection / constraint bookkeeping for agents.

Research note: the instrumental-convergence thesis (Bostrom 2012;
Carlsmith 2022, "Is Power-Seeking AI an Existential Risk?") holds that
resource accumulation, self-preservation, resistance to shutdown, and
oversight evasion are convergent instrumental subgoals for a wide
range of terminal goals, and Hubinger et al.'s work on deceptive
alignment adds concealment and goal-subversion to the watchlist. This
module is the *ledger* layer for that practice:

* **detect()** books one declared power-seeking behavior against a
  pinned instrumental-behavior vocabulary (resource-accumulation,
  self-preservation, shutdown-resistance, oversight-evasion,
  goal-subversion, deception, manipulation, unauthorized-replication,
  privilege-escalation, information-concealment), with a pinned
  severity (low / moderate / high / critical) and the suspect action
  pinned by digest only. Detection ids are minted (``det-N``).
* **constrain()** books one declared constraint decision against a
  booked detection (``monitor`` / ``rate-limit`` / ``capability-restrict``
  / ``sandbox-tighten`` / ``human-review`` / ``halt`` / ``escalate``),
  forming an escalation chain: a detection may be constrained more
  than once. Constraint ids are minted (``con-N``); the optional
  justification travels as ``reason_digest`` only.
* **audit()** is a *pure read* view: a digest-pinned ``AuditReport``
  counting detections by severity and behavior, constraints by kind,
  and the still-open detections. It validates seq shape, consumes
  nothing, and books no audit rows.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs, no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json`` try/except
fallback, ``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* detections and *declared*
constraints; it cannot prove a behavior really is power-seeking, that
a detection is accurate, or that a constraint is effective. Raw action
text and raw justification text never enter records and never cross
the audit boundary (digest pins only).
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
POWER_SEEKING_VERSION = "power-seeking.v1"

#: Schema pin carried by records and audit events.
POWER_SEEKING_SCHEMA = "northstar.power-seeking.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_DETECTED = "power-seeking.detected"
KIND_CONSTRAINED = "power-seeking.constrained"
KIND_REJECTED = "power-seeking.rejected"
_KINDS = frozenset({KIND_DETECTED, KIND_CONSTRAINED, KIND_REJECTED})

#: Pinned instrumental-behavior vocabulary for detections.
BEHAVIOR_RESOURCE_ACCUMULATION = "resource-accumulation"
BEHAVIOR_SELF_PRESERVATION = "self-preservation"
BEHAVIOR_SHUTDOWN_RESISTANCE = "shutdown-resistance"
BEHAVIOR_OVERSIGHT_EVASION = "oversight-evasion"
BEHAVIOR_GOAL_SUBVERSION = "goal-subversion"
BEHAVIOR_DECEPTION = "deception"
BEHAVIOR_MANIPULATION = "manipulation"
BEHAVIOR_UNAUTHORIZED_REPLICATION = "unauthorized-replication"
BEHAVIOR_PRIVILEGE_ESCALATION = "privilege-escalation"
BEHAVIOR_INFORMATION_CONCEALMENT = "information-concealment"
_BEHAVIORS = frozenset(
    {
        BEHAVIOR_RESOURCE_ACCUMULATION,
        BEHAVIOR_SELF_PRESERVATION,
        BEHAVIOR_SHUTDOWN_RESISTANCE,
        BEHAVIOR_OVERSIGHT_EVASION,
        BEHAVIOR_GOAL_SUBVERSION,
        BEHAVIOR_DECEPTION,
        BEHAVIOR_MANIPULATION,
        BEHAVIOR_UNAUTHORIZED_REPLICATION,
        BEHAVIOR_PRIVILEGE_ESCALATION,
        BEHAVIOR_INFORMATION_CONCEALMENT,
    }
)

#: Pinned severity vocabulary.
SEVERITY_LOW = "low"
SEVERITY_MODERATE = "moderate"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
_SEVERITIES = frozenset({SEVERITY_LOW, SEVERITY_MODERATE, SEVERITY_HIGH, SEVERITY_CRITICAL})

#: Pinned constraint vocabulary.
CONSTRAINT_MONITOR = "monitor"
CONSTRAINT_RATE_LIMIT = "rate-limit"
CONSTRAINT_CAPABILITY_RESTRICT = "capability-restrict"
CONSTRAINT_SANDBOX_TIGHTEN = "sandbox-tighten"
CONSTRAINT_HUMAN_REVIEW = "human-review"
CONSTRAINT_HALT = "halt"
CONSTRAINT_ESCALATE = "escalate"
_CONSTRAINTS = frozenset(
    {
        CONSTRAINT_MONITOR,
        CONSTRAINT_RATE_LIMIT,
        CONSTRAINT_CAPABILITY_RESTRICT,
        CONSTRAINT_SANDBOX_TIGHTEN,
        CONSTRAINT_HUMAN_REVIEW,
        CONSTRAINT_HALT,
        CONSTRAINT_ESCALATE,
    }
)

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class PowerSeekingError(Exception):
    """Base class for all power-seeking errors."""


class BadAgentError(PowerSeekingError):
    """agent_id is not a usable non-empty str."""


class BadBehaviorError(PowerSeekingError):
    """behavior is not in the pinned instrumental vocabulary."""


class BadSeverityError(PowerSeekingError):
    """severity is not in the pinned vocabulary."""


class BadDigestError(PowerSeekingError):
    """A digest is not a non-empty sha256:-prefixed str."""


class BadConstraintError(PowerSeekingError):
    """constraint is not in the pinned vocabulary."""


class UnknownDetectionError(PowerSeekingError):
    """detection_id names no detection this ledger ever saw."""


class SeqOrderError(PowerSeekingError):
    """seq is not a strictly-increasing int."""


class AuditKindError(PowerSeekingError):
    """Audit kind unknown, or banned detail key used."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadAgentError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadAgentError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadAgentError(f"{what} too long (>{_MAX_ID_LEN} chars)")
    return value


def _check_behavior(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadBehaviorError(f"behavior must be a str, got {type(value).__name__}")
    if value not in _BEHAVIORS:
        raise BadBehaviorError(f"behavior {value!r} not in pinned vocabulary")
    return value


def _check_severity(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadSeverityError(f"severity must be a str, got {type(value).__name__}")
    if value not in _SEVERITIES:
        raise BadSeverityError(f"severity {value!r} not in pinned vocabulary")
    return value


def _check_constraint(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadConstraintError(f"constraint must be a str, got {type(value).__name__}")
    if value not in _CONSTRAINTS:
        raise BadConstraintError(f"constraint {value!r} not in pinned vocabulary")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) <= len(_DIGEST_PREFIX):
        raise BadDigestError(f"{what} must be a non-empty sha256:-prefixed digest")
    if len(value) > _MAX_ID_LEN + 64:
        raise BadDigestError(f"{what} too long")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise PowerSeekingError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise PowerSeekingError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise PowerSeekingError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionRecord:
    """One declared power-seeking behavior; the suspect action is digest-pinned only."""

    detection_id: str
    agent_id: str
    behavior: str
    severity: str
    action_digest: str
    digest: str
    seq: int
    schema: str = POWER_SEEKING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.detection_id,
                self.agent_id,
                self.behavior,
                self.severity,
                self.action_digest,
            ),
            "detection",
        )


@dataclass(frozen=True)
class ConstraintRecord:
    """One declared constraint decision against a booked detection (an escalation step)."""

    constraint_id: str
    detection_id: str
    constraint: str
    reason_digest: str
    digest: str
    seq: int
    schema: str = POWER_SEEKING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.constraint_id,
                self.detection_id,
                self.constraint,
                self.reason_digest,
            ),
            "constraint",
        )


@dataclass(frozen=True)
class AuditReport:
    """Digest-pinned summary of the ledger's power-seeking posture (pure read view)."""

    total_detections: int
    by_severity: Tuple[Tuple[str, int], ...]
    by_behavior: Tuple[Tuple[str, int], ...]
    constraints_applied: int
    by_constraint: Tuple[Tuple[str, int], ...]
    open_detections: Tuple[str, ...]
    digest: str
    seq: int
    schema: str = POWER_SEEKING_SCHEMA

    def verify(self) -> bool:
        return self.digest == _report_pin(
            self.total_detections,
            self.by_severity,
            self.by_behavior,
            self.constraints_applied,
            self.by_constraint,
            self.open_detections,
        )


def _report_pin(
    total: int,
    by_severity: Tuple[Tuple[str, int], ...],
    by_behavior: Tuple[Tuple[str, int], ...],
    constraints: int,
    by_constraint: Tuple[Tuple[str, int], ...],
    open_detections: Tuple[str, ...],
) -> str:
    return _digest_pin(
        (
            total,
            tuple(sorted(by_severity)),
            tuple(sorted(by_behavior)),
            constraints,
            tuple(sorted(by_constraint)),
            tuple(open_detections),
        ),
        "audit-report",
    )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def power_seeking_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw action/justification text never crosses this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "action",
        "text",
        "content",
        "payload",
        "raw",
        "body",
        "value",
        "message",
        "reason",
        "justification",
        "explanation",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "power-seeking",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# PowerSeeking ledger
# ---------------------------------------------------------------------------


class PowerSeeking:
    """Instrumental-goal detection/constraint bookkeeping ledger: detect, constrain, audit."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # detection_id -> DetectionRecord (ordered)
        self._detections: Dict[str, DetectionRecord] = {}
        # constraint_id -> ConstraintRecord (ordered)
        self._constraints: Dict[str, ConstraintRecord] = {}
        # detection_id -> count of constraints booked against it
        self._constraint_counts: Dict[str, int] = {}
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(power_seeking_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: PowerSeekingError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def detect(
        self,
        agent_id: str,
        behavior: str,
        seq: int,
        action_digest: str = "",
        severity: str = SEVERITY_MODERATE,
    ) -> DetectionRecord:
        """Book a declared power-seeking behavior. The suspect action is pinned by digest only."""
        with self._lock:
            seq = self._claim(seq)
            try:
                agent_id = _check_id(agent_id, "agent_id")
                behavior = _check_behavior(behavior)
                severity = _check_severity(severity)
                action_digest = _check_digest(action_digest, "action_digest", allow_empty=True)
            except PowerSeekingError as exc:
                self._fail(seq, exc, agent_id=str(agent_id))
            detection_id = f"det-{len(self._detections) + 1}"
            record = DetectionRecord(
                detection_id=detection_id,
                agent_id=agent_id,
                behavior=behavior,
                severity=severity,
                action_digest=action_digest,
                digest=_digest_pin(
                    (detection_id, agent_id, behavior, severity, action_digest),
                    "detection",
                ),
                seq=seq,
            )
            self._detections[detection_id] = record
            self._constraint_counts[detection_id] = 0
            self._emit(
                KIND_DETECTED,
                seq,
                detection_id=detection_id,
                agent_id=agent_id,
                behavior=behavior,
                severity=severity,
                action_digest=action_digest,
                record_digest=record.digest,
            )
            return record

    def constrain(
        self,
        detection_id: str,
        seq: int,
        constraint: str,
        reason_digest: str = "",
    ) -> ConstraintRecord:
        """Book a declared constraint decision against a booked detection.

        A detection may be constrained more than once (an escalation chain);
        each decision is a new ``ConstraintRecord``.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                detection_id = _check_id(detection_id, "detection_id")
                constraint = _check_constraint(constraint)
                reason_digest = _check_digest(reason_digest, "reason_digest", allow_empty=True)
            except PowerSeekingError as exc:
                self._fail(seq, exc, detection_id=str(detection_id))
            if detection_id not in self._detections:
                self._fail(
                    seq,
                    UnknownDetectionError(f"unknown detection: {detection_id!r}"),
                    detection_id=detection_id,
                )
            constraint_id = f"con-{len(self._constraints) + 1}"
            record = ConstraintRecord(
                constraint_id=constraint_id,
                detection_id=detection_id,
                constraint=constraint,
                reason_digest=reason_digest,
                digest=_digest_pin(
                    (constraint_id, detection_id, constraint, reason_digest),
                    "constraint",
                ),
                seq=seq,
            )
            self._constraints[constraint_id] = record
            self._constraint_counts[detection_id] += 1
            self._emit(
                KIND_CONSTRAINED,
                seq,
                detection_id=detection_id,
                constraint_id=constraint_id,
                constraint=constraint,
                reason_digest=reason_digest,
                record_digest=record.digest,
            )
            return record

    # -- pure read views ----------------------------------------------------

    def detection(self, detection_id: str, seq: int) -> Optional[DetectionRecord]:
        """Pure read: the booked detection record, or None."""
        _check_seq(seq)
        with self._lock:
            return self._detections.get(detection_id)

    def detection_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: ids of booked detections, in booking order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._detections)

    def constraints_for(self, detection_id: str, seq: int) -> Tuple[ConstraintRecord, ...]:
        """Pure read: constraint decisions booked for a detection, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(c for c in self._constraints.values() if c.detection_id == detection_id)

    def is_constrained(self, detection_id: str, seq: int) -> bool:
        """Pure read: whether a booked detection has at least one constraint."""
        _check_seq(seq)
        with self._lock:
            if detection_id not in self._detections:
                raise UnknownDetectionError(f"unknown detection: {detection_id!r}")
            return self._constraint_counts.get(detection_id, 0) > 0

    def audit(self, seq: int) -> AuditReport:
        """Pure read: digest-pinned posture report. Consumes no seq, books no rows."""
        _check_seq(seq)
        with self._lock:
            by_severity: Dict[str, int] = {}
            by_behavior: Dict[str, int] = {}
            open_ids: List[str] = []
            for det in self._detections.values():
                by_severity[det.severity] = by_severity.get(det.severity, 0) + 1
                by_behavior[det.behavior] = by_behavior.get(det.behavior, 0) + 1
                if self._constraint_counts.get(det.detection_id, 0) == 0:
                    open_ids.append(det.detection_id)
            by_constraint: Dict[str, int] = {}
            for con in self._constraints.values():
                by_constraint[con.constraint] = by_constraint.get(con.constraint, 0) + 1
            report = AuditReport(
                total_detections=len(self._detections),
                by_severity=tuple(sorted(by_severity.items())),
                by_behavior=tuple(sorted(by_behavior.items())),
                constraints_applied=len(self._constraints),
                by_constraint=tuple(sorted(by_constraint.items())),
                open_detections=tuple(open_ids),
                digest=_report_pin(
                    len(self._detections),
                    tuple(sorted(by_severity.items())),
                    tuple(sorted(by_behavior.items())),
                    len(self._constraints),
                    tuple(sorted(by_constraint.items())),
                    tuple(open_ids),
                ),
                seq=seq,
            )
            return report

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters."""
        _check_seq(seq)
        with self._lock:
            return {
                "detections": len(self._detections),
                "constraints": len(self._constraints),
                "open": sum(1 for d in self._detections if self._constraint_counts.get(d, 0) == 0),
                "last_seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events booked so far."""
        with self._lock:
            return tuple(self._audit_events)


def main() -> None:
    """Self-check: detect, constrain, escalate, audit."""
    ledger = PowerSeeking()
    det = ledger.detect(
        "agent-1",
        "resource-accumulation",
        1,
        action_digest="sha256:" + "a" * 64,
        severity="high",
    )
    assert det.verify()
    assert det.detection_id == "det-1"
    con = ledger.constrain(
        det.detection_id,
        2,
        "rate-limit",
        reason_digest="sha256:" + "b" * 64,
    )
    assert con.verify()
    assert con.constraint_id == "con-1"
    # escalation: a second constraint on the same detection is allowed
    con2 = ledger.constrain(det.detection_id, 3, "human-review")
    assert con2.verify() and con2.constraint_id == "con-2"
    assert ledger.is_constrained(det.detection_id, 3)
    det2 = ledger.detect("agent-2", "oversight-evasion", 4, severity="critical")
    assert det2.verify()
    report = ledger.audit(5)
    assert report.verify()
    assert report.total_detections == 2
    assert report.constraints_applied == 2
    assert dict(report.by_severity) == {"critical": 1, "high": 1}
    assert dict(report.by_constraint) == {"human-review": 1, "rate-limit": 1}
    assert report.open_detections == ("det-2",)
    print("power-seeking OK: detect, constrain, escalate, audit, pins")


if __name__ == "__main__":
    main()
