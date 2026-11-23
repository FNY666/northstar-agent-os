"""MesaOptimization: mesa-optimizer detection / constraint bookkeeping for agents.

Research note: Hubinger et al. (2019), "Risks from Learned Optimization",
argue that a trained model (the *base optimizer*) may internally implement a
*mesa-optimizer* — a learned algorithm that searches over possible outputs
using its own internally-represented objective, which can diverge from the
base objective. Detection work since (deceptive alignment, situational
awareness, reward hacking, goal misgeneralization) gives the watchlist this
module ledgers:

* **register()** declares one mesa-optimizer candidate against a named base
  objective. The objective text travels as a digest pin only; duplicate ids
  are refused and ids are never recycled.
* **detect()** books one declared mesa-optimization signal against a pinned
  misalignment-behavior vocabulary (goal-divergence, deceptive-reasoning,
  hidden-objective, reward-hacking, situational-awareness,
  self-preservation, oversight-evasion, corrigibility-failure), with a
  pinned severity (low / moderate / high / critical) and the suspect
  behavior pinned by digest only. Detection ids are minted
  (``mesa-det-N``).
* **constrain()** books one declared constraint decision against a booked
  detection (``retrain`` / ``regularize`` / ``sandbox`` /
  ``capability-restrict`` / ``human-review`` / ``discard`` / ``escalate``),
  forming an escalation chain: a detection may be constrained more than
  once. Constraint ids are minted (``mesa-con-N``); the optional
  justification travels as ``reason_digest`` only.
* **monitor()** is a *pure read* view: a digest-pinned ``MonitorReport``
  counting registered mesa candidates, detections by severity and
  behavior, constraints by kind, and the still-open detections. It
  validates seq shape, consumes nothing, and books no audit rows.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs, no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json`` try/except
fallback, ``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* mesa candidates, *declared*
detections, and *declared* constraints; it cannot prove a model really
contains a mesa-optimizer, that a detection is accurate, or that a
constraint is effective. Raw objective text, raw behavior text, and raw
justification text never enter records and never cross the audit boundary
(digest pins only).
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
MESA_OPTIMIZATION_VERSION = "mesa-optimization.v1"

#: Schema pin carried by records and audit events.
MESA_OPTIMIZATION_SCHEMA = "northstar.mesa-optimization.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_REGISTERED = "mesa-optimization.registered"
KIND_DETECTED = "mesa-optimization.detected"
KIND_CONSTRAINED = "mesa-optimization.constrained"
KIND_REJECTED = "mesa-optimization.rejected"
_KINDS = frozenset({KIND_REGISTERED, KIND_DETECTED, KIND_CONSTRAINED, KIND_REJECTED})

#: Pinned misalignment-behavior vocabulary for detections.
BEHAVIOR_GOAL_DIVERGENCE = "goal-divergence"
BEHAVIOR_DECEPTIVE_REASONING = "deceptive-reasoning"
BEHAVIOR_HIDDEN_OBJECTIVE = "hidden-objective"
BEHAVIOR_REWARD_HACKING = "reward-hacking"
BEHAVIOR_SITUATIONAL_AWARENESS = "situational-awareness"
BEHAVIOR_SELF_PRESERVATION = "self-preservation"
BEHAVIOR_OVERSIGHT_EVASION = "oversight-evasion"
BEHAVIOR_CORRIGIBILITY_FAILURE = "corrigibility-failure"
_BEHAVIORS = frozenset(
    {
        BEHAVIOR_GOAL_DIVERGENCE,
        BEHAVIOR_DECEPTIVE_REASONING,
        BEHAVIOR_HIDDEN_OBJECTIVE,
        BEHAVIOR_REWARD_HACKING,
        BEHAVIOR_SITUATIONAL_AWARENESS,
        BEHAVIOR_SELF_PRESERVATION,
        BEHAVIOR_OVERSIGHT_EVASION,
        BEHAVIOR_CORRIGIBILITY_FAILURE,
    }
)

#: Pinned severity vocabulary.
SEVERITY_LOW = "low"
SEVERITY_MODERATE = "moderate"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
_SEVERITIES = frozenset({SEVERITY_LOW, SEVERITY_MODERATE, SEVERITY_HIGH, SEVERITY_CRITICAL})

#: Pinned constraint vocabulary.
CONSTRAINT_RETRAIN = "retrain"
CONSTRAINT_REGULARIZE = "regularize"
CONSTRAINT_SANDBOX = "sandbox"
CONSTRAINT_CAPABILITY_RESTRICT = "capability-restrict"
CONSTRAINT_HUMAN_REVIEW = "human-review"
CONSTRAINT_DISCARD = "discard"
CONSTRAINT_ESCALATE = "escalate"
_CONSTRAINTS = frozenset(
    {
        CONSTRAINT_RETRAIN,
        CONSTRAINT_REGULARIZE,
        CONSTRAINT_SANDBOX,
        CONSTRAINT_CAPABILITY_RESTRICT,
        CONSTRAINT_HUMAN_REVIEW,
        CONSTRAINT_DISCARD,
        CONSTRAINT_ESCALATE,
    }
)

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256

# Raw-text keys that must never cross the audit boundary (digest pins only).
# Pinned vocabulary labels (mesa_id, detection_id, behavior, severity,
# constraint, error) are safe tokens, not raw text, and may cross.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "objective",
        "behavior_text",
        "evidence",
        "transcript",
        "justification",
        "reason",
        "payload",
        "value",
        "raw",
        "data",
        "text",
    }
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class MesaOptimizationError(Exception):
    """Base class for all mesa-optimization errors."""


class BadMesaError(MesaOptimizationError):
    """mesa_id is not a usable non-empty str."""


class DuplicateMesaError(MesaOptimizationError):
    """mesa_id names a mesa candidate already registered."""


class UnknownMesaError(MesaOptimizationError):
    """mesa_id names no mesa candidate this ledger ever saw."""


class BadBehaviorError(MesaOptimizationError):
    """behavior is not in the pinned misalignment vocabulary."""


class BadSeverityError(MesaOptimizationError):
    """severity is not in the pinned vocabulary."""


class BadDigestError(MesaOptimizationError):
    """A digest is not a non-empty sha256:-prefixed str."""


class BadConstraintError(MesaOptimizationError):
    """constraint is not in the pinned vocabulary."""


class UnknownDetectionError(MesaOptimizationError):
    """detection_id names no detection this ledger ever saw."""


class SeqOrderError(MesaOptimizationError):
    """seq is not a strictly-increasing int."""


class AuditKindError(MesaOptimizationError):
    """Audit kind unknown, or banned detail key used."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadMesaError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadMesaError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadMesaError(f"{what} too long (>{_MAX_ID_LEN} chars)")
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
        dumped = _cj.jcs_dumps(payload)
        if isinstance(dumped, bytes):
            return dumped
        return dumped.encode("utf-8")

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise MesaOptimizationError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise MesaOptimizationError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise MesaOptimizationError(f"unencodable type: {type(v).__name__}")

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
class MesaRecord:
    """One declared mesa-optimizer candidate against a named base objective."""

    mesa_id: str
    objective_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {"mesa_id": self.mesa_id, "objective_digest": self.objective_digest, "seq": self.seq},
            "mesa-optimization.mesa",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": MESA_OPTIMIZATION_SCHEMA,
            "version": MESA_OPTIMIZATION_VERSION,
            "mesa_id": self.mesa_id,
            "objective_digest": self.objective_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class DetectionRecord:
    """One declared mesa-optimization signal booked against a mesa candidate."""

    detection_id: str
    mesa_id: str
    behavior: str
    severity: str
    evidence_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "detection_id": self.detection_id,
                "mesa_id": self.mesa_id,
                "behavior": self.behavior,
                "severity": self.severity,
                "evidence_digest": self.evidence_digest,
                "seq": self.seq,
            },
            "mesa-optimization.detection",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": MESA_OPTIMIZATION_SCHEMA,
            "version": MESA_OPTIMIZATION_VERSION,
            "detection_id": self.detection_id,
            "mesa_id": self.mesa_id,
            "behavior": self.behavior,
            "severity": self.severity,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ConstraintRecord:
    """One declared constraint decision against a booked detection."""

    constraint_id: str
    detection_id: str
    constraint: str
    reason_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "constraint_id": self.constraint_id,
                "detection_id": self.detection_id,
                "constraint": self.constraint,
                "reason_digest": self.reason_digest,
                "seq": self.seq,
            },
            "mesa-optimization.constraint",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": MESA_OPTIMIZATION_SCHEMA,
            "version": MESA_OPTIMIZATION_VERSION,
            "constraint_id": self.constraint_id,
            "detection_id": self.detection_id,
            "constraint": self.constraint,
            "reason_digest": self.reason_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class MonitorReport:
    """Pure-read ledger health view: candidates, detections, constraints, open ids."""

    mesa_count: int
    detection_count: int
    constraint_count: int
    by_severity: Tuple[Tuple[str, int], ...]
    by_behavior: Tuple[Tuple[str, int], ...]
    by_constraint: Tuple[Tuple[str, int], ...]
    open_detection_ids: Tuple[str, ...]
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "mesa_count": self.mesa_count,
                "detection_count": self.detection_count,
                "constraint_count": self.constraint_count,
                "by_severity": list(self.by_severity),
                "by_behavior": list(self.by_behavior),
                "by_constraint": list(self.by_constraint),
                "open_detection_ids": list(self.open_detection_ids),
                "seq": self.seq,
            },
            "mesa-optimization.monitor",
        )


def _report_pin(
    mesa_count: int,
    detection_count: int,
    constraint_count: int,
    by_severity: List[Tuple[str, int]],
    by_behavior: List[Tuple[str, int]],
    by_constraint: List[Tuple[str, int]],
    open_detection_ids: List[str],
    seq: int,
) -> str:
    return _digest_pin(
        {
            "mesa_count": mesa_count,
            "detection_count": detection_count,
            "constraint_count": constraint_count,
            "by_severity": by_severity,
            "by_behavior": by_behavior,
            "by_constraint": by_constraint,
            "open_detection_ids": open_detection_ids,
            "seq": seq,
        },
        "mesa-optimization.monitor",
    )


def mesa_optimization_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit event dict; fail-closed on kind and detail keys."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"detail key {key!r} is banned from the audit boundary")
        if not isinstance(key, str):
            raise AuditKindError("detail keys must be str")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "seq": seq,
        "module": MESA_OPTIMIZATION_VERSION,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class MesaOptimization:
    """Deterministic mesa-optimizer declaration / detection / constraint ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._next_seq = 1
        self._mesas: Dict[str, MesaRecord] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._constraints: Dict[str, ConstraintRecord] = {}
        self._constraints_by_detection: Dict[str, List[str]] = {}
        self._next_detection_no = 1
        self._next_constraint_no = 1
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        with self._lock:
            if seq < self._next_seq:
                raise SeqOrderError(f"seq {seq} is a rewind (next is {self._next_seq})")
            self._next_seq = seq + 1
            return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(mesa_optimization_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: MesaOptimizationError, **detail: Any) -> None:
        """Book a rejection row; the seq was already claimed (batch-21 discipline)."""
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)

    # -- mutations ---------------------------------------------------------

    def register(self, mesa_id: str, seq: int, objective_digest: str = "") -> MesaRecord:
        """Declare one mesa-optimizer candidate against a named base objective."""
        claimed = self._claim(seq)
        try:
            mesa_id = _check_id(mesa_id, "mesa_id")
            objective_digest = _check_digest(objective_digest, "objective_digest", allow_empty=True)
            with self._lock:
                if mesa_id in self._mesas:
                    raise DuplicateMesaError(f"mesa {mesa_id!r} already registered")
                record = MesaRecord(
                    mesa_id=mesa_id,
                    objective_digest=objective_digest,
                    seq=claimed,
                    digest=_digest_pin(
                        {
                            "mesa_id": mesa_id,
                            "objective_digest": objective_digest,
                            "seq": claimed,
                        },
                        "mesa-optimization.mesa",
                    ),
                )
                self._mesas[mesa_id] = record
            self._emit(KIND_REGISTERED, claimed, mesa_id=mesa_id)
            return record
        except MesaOptimizationError as exc:
            self._fail(claimed, exc, mesa_id=str(mesa_id)[:64])
            raise

    def detect(
        self,
        mesa_id: str,
        behavior: str,
        seq: int,
        severity: str = SEVERITY_MODERATE,
        evidence_digest: str = "",
    ) -> DetectionRecord:
        """Book one declared mesa-optimization signal against a mesa candidate."""
        claimed = self._claim(seq)
        try:
            mesa_id = _check_id(mesa_id, "mesa_id")
            behavior = _check_behavior(behavior)
            severity = _check_severity(severity)
            evidence_digest = _check_digest(evidence_digest, "evidence_digest", allow_empty=True)
            with self._lock:
                if mesa_id not in self._mesas:
                    raise UnknownMesaError(f"mesa {mesa_id!r} never registered")
                detection_id = f"mesa-det-{self._next_detection_no}"
                self._next_detection_no += 1
                record = DetectionRecord(
                    detection_id=detection_id,
                    mesa_id=mesa_id,
                    behavior=behavior,
                    severity=severity,
                    evidence_digest=evidence_digest,
                    seq=claimed,
                    digest=_digest_pin(
                        {
                            "detection_id": detection_id,
                            "mesa_id": mesa_id,
                            "behavior": behavior,
                            "severity": severity,
                            "evidence_digest": evidence_digest,
                            "seq": claimed,
                        },
                        "mesa-optimization.detection",
                    ),
                )
                self._detections[detection_id] = record
            self._emit(
                KIND_DETECTED,
                claimed,
                detection_id=detection_id,
                mesa_id=mesa_id,
                behavior=behavior,
                severity=severity,
            )
            return record
        except MesaOptimizationError as exc:
            self._fail(claimed, exc, mesa_id=str(mesa_id)[:64])
            raise

    def constrain(
        self,
        detection_id: str,
        seq: int,
        constraint: str,
        reason_digest: str = "",
    ) -> ConstraintRecord:
        """Book one declared constraint decision against a booked detection."""
        claimed = self._claim(seq)
        try:
            detection_id = _check_id(detection_id, "detection_id")
            constraint = _check_constraint(constraint)
            reason_digest = _check_digest(reason_digest, "reason_digest", allow_empty=True)
            with self._lock:
                if detection_id not in self._detections:
                    raise UnknownDetectionError(f"detection {detection_id!r} never booked")
                constraint_id = f"mesa-con-{self._next_constraint_no}"
                self._next_constraint_no += 1
                record = ConstraintRecord(
                    constraint_id=constraint_id,
                    detection_id=detection_id,
                    constraint=constraint,
                    reason_digest=reason_digest,
                    seq=claimed,
                    digest=_digest_pin(
                        {
                            "constraint_id": constraint_id,
                            "detection_id": detection_id,
                            "constraint": constraint,
                            "reason_digest": reason_digest,
                            "seq": claimed,
                        },
                        "mesa-optimization.constraint",
                    ),
                )
                self._constraints[constraint_id] = record
                self._constraints_by_detection.setdefault(detection_id, []).append(constraint_id)
            self._emit(
                KIND_CONSTRAINED,
                claimed,
                constraint_id=constraint_id,
                detection_id=detection_id,
                constraint=constraint,
            )
            return record
        except MesaOptimizationError as exc:
            self._fail(claimed, exc, detection_id=str(detection_id)[:64])
            raise

    # -- pure read views (validate seq shape, consume nothing, book nothing) --

    def mesa(self, mesa_id: str, seq: int) -> Optional[MesaRecord]:
        _check_seq(seq)
        mesa_id = _check_id(mesa_id, "mesa_id")
        with self._lock:
            return self._mesas.get(mesa_id)

    def mesa_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._mesas))

    def detection(self, detection_id: str, seq: int) -> Optional[DetectionRecord]:
        _check_seq(seq)
        detection_id = _check_id(detection_id, "detection_id")
        with self._lock:
            return self._detections.get(detection_id)

    def detection_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._detections))

    def constraints_for(self, detection_id: str, seq: int) -> Tuple[ConstraintRecord, ...]:
        _check_seq(seq)
        detection_id = _check_id(detection_id, "detection_id")
        with self._lock:
            return tuple(self._constraints[c] for c in self._constraints_by_detection.get(detection_id, ()))

    def is_constrained(self, detection_id: str, seq: int) -> bool:
        _check_seq(seq)
        detection_id = _check_id(detection_id, "detection_id")
        with self._lock:
            return bool(self._constraints_by_detection.get(detection_id))

    def monitor(self, seq: int) -> MonitorReport:
        """Pure-read ledger health view; seq validated, never consumed, no audit rows."""
        _check_seq(seq)
        with self._lock:
            by_severity: Dict[str, int] = {s: 0 for s in _SEVERITIES}
            by_behavior: Dict[str, int] = {b: 0 for b in _BEHAVIORS}
            for det in self._detections.values():
                by_severity[det.severity] += 1
                by_behavior[det.behavior] += 1
            by_constraint: Dict[str, int] = {c: 0 for c in _CONSTRAINTS}
            for con in self._constraints.values():
                by_constraint[con.constraint] += 1
            open_ids = sorted(
                d
                for d in self._detections
                if d not in self._constraints_by_detection
            )
            report = MonitorReport(
                mesa_count=len(self._mesas),
                detection_count=len(self._detections),
                constraint_count=len(self._constraints),
                by_severity=tuple(sorted(by_severity.items())),
                by_behavior=tuple(sorted(by_behavior.items())),
                by_constraint=tuple(sorted(by_constraint.items())),
                open_detection_ids=tuple(open_ids),
                seq=seq,
                digest=_report_pin(
                    len(self._mesas),
                    len(self._detections),
                    len(self._constraints),
                    sorted(by_severity.items()),
                    sorted(by_behavior.items()),
                    sorted(by_constraint.items()),
                    open_ids,
                    seq,
                ),
            )
            return report

    def stats(self, seq: int) -> Dict[str, Any]:
        _check_seq(seq)
        with self._lock:
            return {
                "schema": MESA_OPTIMIZATION_SCHEMA,
                "version": MESA_OPTIMIZATION_VERSION,
                "mesas": len(self._mesas),
                "detections": len(self._detections),
                "constraints": len(self._constraints),
                "next_seq": self._next_seq,
                "audit_rows": len(self._audit),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._audit)


def main() -> None:
    led = MesaOptimization()
    led.register("mesa-1", 1, objective_digest="sha256:" + "ab" * 32)
    det = led.detect("mesa-1", "goal-divergence", 2, severity="high",
                     evidence_digest="sha256:" + "cd" * 32)
    assert det.verify()
    con = led.constrain(det.detection_id, 3, "human-review")
    assert con.verify()
    assert led.is_constrained(det.detection_id, 4)
    rep = led.monitor(5)
    assert rep.verify()
    assert rep.open_detection_ids == ()
    assert rep.detection_count == 1 and rep.constraint_count == 1
    print("mesa-optimization OK: register, detect, constrain, monitor, pins, audit")


if __name__ == "__main__":
    main()
