"""AI evaluation: declared-evaluation decision ledger, Simulated.

Research note: model evaluation (benchmarks, red-teaming, human
review, automated metrics, field trials) never *proves* a model is
capable, safe, or aligned - evals are run by the host under a declared
configuration, scores are host claims, and every verdict is booked as
data. What matters here is the *decision ledger*: which systems
underwent which declared evaluation kinds, what findings were
declared with what evidence digest pins, and how each evaluation
itself was meta-evaluated - defensible bookkeeping, never proof that
any system actually passed (or failed) anything.

This module owns the assess -> evaluate -> verify lifecycle:

* **assess()** - book one declared evaluation assessment for a system
  (minted ``asm-N`` ids; pinned 8-term evaluation-kind vocabulary and
  pinned finding vocabulary ``pass`` / ``marginal`` / ``fail`` /
  ``inconclusive`` / ``not-assessed``). The first assessment
  registers its system. Raw scores, transcripts, benchmark material,
  and judge internals never enter records - digest pins only.
* **evaluate()** - book one declared meta-evaluation of an assessment
  (minted ``evl-N`` ids; pinned outcome vocabulary ``accepted`` /
  ``rejected`` / ``inconclusive`` / ``superseded``), booked **as
  data**, never proof the assessment was well-run. Fail-closed on
  unknown assessments, retired systems, and double-evaluation.
* **verify()** - pure read: re-derive the digest pin of any assessment
  or evaluation record; verdict ``verified`` / ``tampered`` booked as
  data (tamper reported, never raised).
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale: ``ai_assurance.py`` owns assurance
statements, ``ai_audit.py`` owns audit execution, benchmark/eval
mechanics modules own *how* evals run - this module is the evaluation
*declaration* ledger none of them own: system -> declared evaluation
kind -> declared finding -> declared meta-evaluation outcome.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-evaluation.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no evals, scores no benchmarks,
judges no systems, and proves nothing about real capability or
safety. A booked ``pass`` finding means "the host declared it", never
"the system is safe". Scores, transcripts, benchmark data, prompts,
judge notes, and model internals never enter records or cross the
audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
AI_EVALUATION_VERSION = "ai-evaluation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-evaluation.v1"

#: Pinned evaluation-kind vocabulary (the evaluation kinds this ledger tracks).
ASSESSMENT_KINDS = (
    "capability-eval",
    "safety-eval",
    "alignment-eval",
    "robustness-eval",
    "fairness-eval",
    "security-eval",
    "governance-eval",
    "field-eval",
)

#: Pinned assessment-finding vocabulary (booked as data, never proof).
FINDINGS = (
    "pass",
    "marginal",
    "fail",
    "inconclusive",
    "not-assessed",
)

#: Pinned meta-evaluation outcome vocabulary (booked as data, never proof).
EVAL_OUTCOMES = (
    "accepted",
    "rejected",
    "inconclusive",
    "superseded",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "assessed",
    "evaluated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "scores",
        "score",
        "scores_by_item",
        "benchmark",
        "benchmarks",
        "dataset",
        "datasets",
        "responses",
        "response",
        "transcripts",
        "transcript",
        "prompts",
        "prompt",
        "model_output",
        "model_outputs",
        "outputs",
        "judge",
        "judge_notes",
        "reviewer",
        "reviewers",
        "ratings",
        "metrics",
        "metric",
        "eval_log",
        "eval_logs",
        "traces",
        "trace",
        "weights",
        "model_weights",
        "parameters",
        "params",
        "trajectory",
        "trajectories",
        "action",
        "actions",
        "state",
        "states",
        "observation",
        "reward",
        "rewards",
        "loss",
        "feedback",
        "preference",
        "payload",
        "content",
        "text",
        "note",
        "notes",
        "detail",
        "details",
        "description",
        "report",
        "evidence",
        "result",
        "results",
        "raw",
        "secret",
        "key",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIEvaluationError(Exception):
    """Base error for AI-evaluation ledger misuse."""


class BadIdError(AIEvaluationError):
    """Malformed system, assessment, or evaluation id."""


class RetiredSystemError(AIEvaluationError):
    """System id already retired; never recycled."""


class UnknownSystemError(AIEvaluationError):
    """System not registered."""


class BadAssessmentKindError(AIEvaluationError):
    """Unknown evaluation kind."""


class BadFindingError(AIEvaluationError):
    """Unknown assessment finding."""


class BadSeverityError(AIEvaluationError):
    """Severity is not a host-reported int in [0, 100]."""


class BadDigestError(AIEvaluationError):
    """Malformed sha256: digest pin."""


class UnknownAssessmentError(AIEvaluationError):
    """Assessment id not booked (or record id unknown)."""


class BadOutcomeError(AIEvaluationError):
    """Unknown meta-evaluation outcome."""


class AlreadyEvaluatedError(AIEvaluationError):
    """Assessment already has a booked evaluation."""


class BadReasonError(AIEvaluationError):
    """Unknown retirement reason."""


class SeqOrderError(AIEvaluationError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(AIEvaluationError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_severity(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError(f"{field_name} must be an int in [0, 100], not bool")
    if value < 0 or value > 100:
        raise BadSeverityError(f"{field_name} must be an int in [0, 100]")
    return value


def _require_digest(pin: Any, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    assessment_id: str
    system_id: str
    assessment_kind: str
    finding: str
    severity: int
    assessment_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "assessment_id": self.assessment_id,
            "system_id": self.system_id,
            "assessment_kind": self.assessment_kind,
            "finding": self.finding,
            "severity": self.severity,
            "assessment_digest": self.assessment_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "assessment_id": self.assessment_id,
                "system_id": self.system_id,
                "assessment_kind": self.assessment_kind,
                "finding": self.finding,
                "severity": self.severity,
                "assessment_digest": self.assessment_digest,
            }
        )


@dataclass(frozen=True)
class EvaluationRecord:
    evaluation_id: str
    assessment_id: str
    system_id: str
    outcome: str
    evaluation_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "evaluation_id": self.evaluation_id,
            "assessment_id": self.assessment_id,
            "system_id": self.system_id,
            "outcome": self.outcome,
            "evaluation_digest": self.evaluation_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "evaluation_id": self.evaluation_id,
                "assessment_id": self.assessment_id,
                "system_id": self.system_id,
                "outcome": self.outcome,
                "evaluation_digest": self.evaluation_digest,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    record_kind: str
    verdict: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "verdict": self.verdict,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "record_id": self.record_id,
                "record_kind": self.record_kind,
                "verdict": self.verdict,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ai_evaluation_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the AI-evaluation ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIEvaluation:
    """AI-evaluation decision ledger, Simulated.

    ``assess()`` / ``evaluate()`` / ``retire()`` mutate the ledger and
    consume caller seqs; ``verify()`` and the other views are pure
    reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._assessments_by_system: Dict[str, List[str]] = {}
        self._evaluations: Dict[str, EvaluationRecord] = {}
        self._evaluations_by_assessment: Dict[str, str] = {}
        self._evaluations_by_system: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._asm_counter = 0
        self._evl_counter = 0
        self._seq = 0
        self._audit: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int, not bool")
        return seq

    def _claim_seq(self, seq: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq} after {self._seq}"
            )
        self._seq = seq

    def _burn(self, seq: int, method: str, exc: AIEvaluationError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            ai_evaluation_audit_event(
                "rejected",
                seq,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _require_live_system(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system already retired: {system_id!r}")

    def _require_known_system(self, system_id: str) -> None:
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    # -- mutations --------------------------------------------------------

    def assess(
        self,
        system_id: Any,
        seq: Any,
        assessment_kind: Any = "safety-eval",
        finding: Any = "not-assessed",
        severity: Any = 0,
        assessment_digest: Any = "",
    ) -> AssessmentRecord:
        """Book one declared evaluation assessment (minted ``asm-N``).

        The first assessment registers its system. Severity is a
        host-reported int in [0, 100] booked as data. Raw scores,
        transcripts, benchmark material, and judge internals travel as
        a digest pin only; they never enter records.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if not isinstance(assessment_kind, str) or assessment_kind not in ASSESSMENT_KINDS:
                    raise BadAssessmentKindError(
                        f"assessment_kind must be one of {sorted(ASSESSMENT_KINDS)}"
                    )
                if not isinstance(finding, str) or finding not in FINDINGS:
                    raise BadFindingError(f"finding must be one of {sorted(FINDINGS)}")
                sev = _require_severity(severity, "severity")
                pin = _require_digest(assessment_digest, "assessment_digest")
                self._asm_counter += 1
                aid = f"asm-{self._asm_counter}"
                rec = AssessmentRecord(
                    assessment_id=aid,
                    system_id=sid,
                    assessment_kind=assessment_kind,
                    finding=finding,
                    severity=sev,
                    assessment_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "assessment_id": aid,
                            "system_id": sid,
                            "assessment_kind": assessment_kind,
                            "finding": finding,
                            "severity": sev,
                            "assessment_digest": pin,
                        }
                    ),
                )
                self._assessments[aid] = rec
                self._systems.setdefault(sid, []).append(aid)
                self._assessments_by_system.setdefault(sid, []).append(aid)
                self._audit.append(
                    ai_evaluation_audit_event(
                        "assessed",
                        seq_v,
                        assessment_id=aid,
                        system_id=sid,
                        assessment_kind=assessment_kind,
                        finding=finding,
                        severity=sev,
                    )
                )
                return rec
            except AIEvaluationError as exc:
                self._burn(seq_v, "assess", exc)
                raise

    def evaluate(
        self,
        assessment_id: Any,
        seq: Any,
        outcome: Any = "inconclusive",
        evaluation_digest: Any = "",
    ) -> EvaluationRecord:
        """Book one declared meta-evaluation of an assessment (minted ``evl-N``).

        Outcomes are booked **as data**, never proof the assessment was
        well-run. Fail-closed on unknown assessments, retired systems,
        and double-evaluation.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                aid = _require_id(assessment_id, "assessment_id")
                asm = self._assessments.get(aid)
                if asm is None:
                    raise UnknownAssessmentError(f"unknown assessment: {aid!r}")
                self._require_live_system(asm.system_id)
                if not isinstance(outcome, str) or outcome not in EVAL_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(EVAL_OUTCOMES)}"
                    )
                if aid in self._evaluations_by_assessment:
                    raise AlreadyEvaluatedError(
                        f"assessment already evaluated: {aid!r}"
                    )
                pin = _require_digest(evaluation_digest, "evaluation_digest")
                self._evl_counter += 1
                eid = f"evl-{self._evl_counter}"
                rec = EvaluationRecord(
                    evaluation_id=eid,
                    assessment_id=aid,
                    system_id=asm.system_id,
                    outcome=outcome,
                    evaluation_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "evaluation_id": eid,
                            "assessment_id": aid,
                            "system_id": asm.system_id,
                            "outcome": outcome,
                            "evaluation_digest": pin,
                        }
                    ),
                )
                self._evaluations[eid] = rec
                self._evaluations_by_assessment[aid] = eid
                self._evaluations_by_system.setdefault(asm.system_id, []).append(eid)
                self._audit.append(
                    ai_evaluation_audit_event(
                        "evaluated",
                        seq_v,
                        evaluation_id=eid,
                        assessment_id=aid,
                        system_id=asm.system_id,
                        outcome=outcome,
                    )
                )
                return rec
            except AIEvaluationError as exc:
                self._burn(seq_v, "evaluate", exc)
                raise

    def retire(
        self,
        system_id: Any,
        seq: Any,
        reason: Any = "manual",
    ) -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system already retired: {sid!r}")
                self._require_known_system(sid)
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(RETIRE_REASONS)}"
                    )
                rec = RetireRecord(
                    system_id=sid,
                    reason=reason,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "system_id": sid,
                            "reason": reason,
                        }
                    ),
                )
                self._retired[sid] = rec
                self._audit.append(
                    ai_evaluation_audit_event(
                        "retired",
                        seq_v,
                        system_id=sid,
                        reason=reason,
                    )
                )
                return rec
            except AIEvaluationError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def assessment_record(self, assessment_id: Any, seq: Any) -> AssessmentRecord:
        """Return one assessment record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            aid = _require_id(assessment_id, "assessment_id")
            if aid not in self._assessments:
                raise UnknownAssessmentError(f"unknown assessment: {aid!r}")
            return self._assessments[aid]

    def evaluation_record(self, evaluation_id: Any, seq: Any) -> EvaluationRecord:
        """Return one evaluation record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            eid = _require_id(evaluation_id, "evaluation_id")
            if eid not in self._evaluations:
                raise UnknownAssessmentError(f"unknown evaluation: {eid!r}")
            return self._evaluations[eid]

    def evaluation_for(self, assessment_id: Any, seq: Any) -> str:
        """Evaluation id booked against one assessment, if any (pure read)."""
        with self._lock:
            self._check_seq(seq)
            aid = _require_id(assessment_id, "assessment_id")
            if aid not in self._assessments:
                raise UnknownAssessmentError(f"unknown assessment: {aid!r}")
            if aid not in self._evaluations_by_assessment:
                raise UnknownAssessmentError(
                    f"no evaluation for assessment: {aid!r}"
                )
            return self._evaluations_by_assessment[aid]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def assessment_ids(self, seq: Any) -> Tuple[str, ...]:
        """All assessment ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"asm-{i}" for i in range(1, self._asm_counter + 1))

    def evaluation_ids(self, seq: Any) -> Tuple[str, ...]:
        """All evaluation ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"evl-{i}" for i in range(1, self._evl_counter + 1))

    def assessments_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Assessment ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._assessments_by_system[sid])

    def evaluations_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Evaluation ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._evaluations_by_system.get(sid, ()))

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """All retired system ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def verify(self, record_id: Any, seq: Any) -> VerificationReport:
        """Re-derive the digest pin of any assessment or evaluation record.

        Pure read: seq shape validated only, never consumed, no audit
        row. Verdict ``verified`` / ``tampered`` is booked as data;
        tamper is reported, never raised.
        """
        with self._lock:
            self._check_seq(seq)
            rid = _require_id(record_id, "record_id")
            if rid in self._assessments:
                rec = self._assessments[rid]
                kind = "assessment"
            elif rid in self._evaluations:
                rec = self._evaluations[rid]
                kind = "evaluation"
            else:
                raise UnknownAssessmentError(f"unknown record: {rid!r}")
            verdict = "verified" if rec.verify() else "tampered"
            return VerificationReport(
                record_id=rid,
                record_kind=kind,
                verdict=verdict,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "record_id": rid,
                        "record_kind": kind,
                        "verdict": verdict,
                    }
                ),
            )

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: Any) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "systems": len(self._systems),
                "assessments": len(self._assessments),
                "evaluations": len(self._evaluations),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    ae = AIEvaluation()
    pin = "sha256:" + "ab" * 32
    asm = ae.assess(
        "sys-1",
        1,
        assessment_kind="capability-eval",
        finding="pass",
        severity=10,
        assessment_digest=pin,
    )
    assert asm.assessment_id == "asm-1"
    evl = ae.evaluate("asm-1", 2, outcome="accepted", evaluation_digest=pin)
    assert evl.evaluation_id == "evl-1"
    rep = ae.verify("asm-1", 3)
    assert rep.verdict == "verified"
    rep2 = ae.verify("evl-1", 3)
    assert rep2.verdict == "verified"
    ae.retire("sys-1", 4, reason="decommissioned")
    assert ae.stats(5) == {
        "systems": 1,
        "assessments": 1,
        "evaluations": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("ai-evaluation OK: assess, evaluate, verify, retire, pins, audit")


if __name__ == "__main__":
    main()
