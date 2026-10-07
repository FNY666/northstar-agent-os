"""AI resilience: resilience assessment -> strengthening decision ledger, Simulated.

Research note: AI resilience is the field concerned with how AI systems
keep functioning - safely degrading, recovering, and restoring service -
when components fail, inputs go adversarial, load spikes, dependencies
drop, or the world drifts off-distribution. This module is the *decision
ledger* for declared AI-resilience assessments: which systems had which
resilience aspects booked (over a pinned resilience-kind vocabulary),
what verdicts the host declared against them, which strengthenings the
host declared, and what resilience posture the ledger derives - defensible
bookkeeping, never proof that a system is really resilient.

This module owns the assess -> strengthen -> verify lifecycle:

* **assess()** - book one declared resilience assessment (minted
  ``asm-N`` ids; pinned resilience-kind vocabulary over the common
  resilience aspects; pinned verdict vocabulary booked *as data*);
  host-reported severity is an int in [0,100]; the first assessment
  registers its system; raw evidence (fault traces, failover logs,
  chaos-run outputs, weights) never enters records - digest pins only.
* **strengthen()** - book one declared strengthening against an
  assessment (minted ``str-N`` ids; pinned strategy vocabulary booked
  *as data*; repeatable chain; fail-closed on unknown assessments and
  retired systems); books the *declaration*, never the deployed fix.
* **verify()** - **pure read**: re-derive one assessment or
  strengthening record's digest pin; verdict ``verified`` /
  ``tampered`` booked as data, never as proof the assessment really
  ran or the strengthening really deployed.
* **evaluate()** - **pure read**: derive one system's resilience
  posture as data (``unassessed`` -> ``brittle`` -> ``uncertain`` ->
  ``strengthened`` -> ``resilient``) with verdict tallies and a
  digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_robustness.py`` owns the
robustness *test* governance ledger (test kinds and host-declared
outcomes under distribution shift / adversarial pressure);
``robustness_testing.py`` owns perturbation mechanics;
``ai_safety.py`` owns the safety assessment -> mitigation lifecycle;
``resilience.py`` / fault-tolerance layers own operational mechanics -
this module is the AI-resilience *assessment -> strengthening*
decision ledger none of them own: declared resilience assessments over
the pinned resilience-kind vocabulary, declared strengthenings, digest
re-derivation, and the ledger-rule posture that turns declared verdicts
into a resilience claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-resilience.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no systems, executes
no assessments, and proves nothing about real AI resilience. A booked
``resilient`` verdict means "the host declared it", never "the system is
resilient". Fault traces, failover logs, chaos-run outputs, weights,
prompts, and raw evidence never enter records or cross the audit
boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_RESILIENCE_VERSION = "ai-resilience.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-resilience.v1"

#: Pinned resilience-kind vocabulary (the resilience aspects booked).
RESILIENCE_KINDS = (
    "fault-recovery",
    "graceful-degradation",
    "failover",
    "self-healing",
    "redundancy",
    "rollback",
    "contingency",
    "drift-resilience",
)

#: Pinned assessment-verdict vocabulary (booked as data, never proof).
ASSESS_VERDICTS = (
    "resilient",
    "at-risk",
    "brittle",
    "inconclusive",
    "not-assessed",
)

#: Pinned strengthening-strategy vocabulary (booked as data, never proof).
STRENGTHEN_STRATEGIES = (
    "redundancy-add",
    "failover-drill",
    "graceful-degradation",
    "rollback-plan",
    "monitoring-escalation",
    "diversity-injection",
    "checkpointing",
    "no-action",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unassessed",
    "brittle",
    "uncertain",
    "strengthened",
    "resilient",
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
    "strengthened",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "checkpoint_data",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "heartbeat",
        "behavior",
        "perturbation",
        "perturbations",
        "noise",
        "sample",
        "samples",
        "dataset",
        "example",
        "examples",
        "input",
        "inputs",
        "score",
        "scores",
        "metric",
        "metrics",
        "loss",
        "fault_trace",
        "fault_traces",
        "failover_log",
        "failover_logs",
        "chaos_run",
        "chaos_runs",
        "incident",
        "incidents",
        "recovery_trace",
        "error_rate",
        "downtime",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIResilienceError(Exception):
    """Base class for all ai-resilience ledger errors."""


class BadSystemError(AIResilienceError):
    pass


class UnknownSystemError(AIResilienceError):
    pass


class RetiredSystemError(AIResilienceError):
    pass


class BadResilienceKindError(AIResilienceError):
    pass


class BadVerdictError(AIResilienceError):
    pass


class BadSeverityError(AIResilienceError):
    pass


class BadDigestError(AIResilienceError):
    pass


class BadStrategyError(AIResilienceError):
    pass


class UnknownAssessmentError(AIResilienceError):
    pass


class UnknownRecordError(AIResilienceError):
    pass


class BadReasonError(AIResilienceError):
    pass


class SeqOrderError(AIResilienceError):
    pass


class AuditKindError(AIResilienceError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_resilience_kind(value: Any) -> str:
    if value not in RESILIENCE_KINDS:
        raise BadResilienceKindError(f"resilience_kind must be one of {RESILIENCE_KINDS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in ASSESS_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {ASSESS_VERDICTS}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise BadSeverityError("severity must be an int in [0, 100]")
    return value


def _check_strategy(value: Any) -> str:
    if value not in STRENGTHEN_STRATEGIES:
        raise BadStrategyError(f"strategy must be one of {STRENGTHEN_STRATEGIES}")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    assessment_id: str
    system_id: str
    seq: int
    resilience_kind: str
    verdict: str
    severity: int
    assessment_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _assess_payload(self), "ai-resilience.assess"
        )


@dataclass(frozen=True)
class StrengtheningRecord:
    strengthening_id: str
    assessment_id: str
    system_id: str
    seq: int
    strategy: str
    strengthening_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _strengthen_payload(self), "ai-resilience.strengthen"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "ai-resilience.retire")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_verify_payload(self), "ai-resilience.verify")


@dataclass(frozen=True)
class ResilienceReport:
    system_id: str
    seq: int
    posture: str
    n_assessments: int
    n_resilient: int
    n_at_risk: int
    n_brittle: int
    n_inconclusive: int
    n_not_assessed: int
    n_strengthened: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-resilience.evaluate"
        )


def _assess_payload(rec: "AssessmentRecord") -> Dict[str, Any]:
    return {
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "resilience_kind": rec.resilience_kind,
        "verdict": rec.verdict,
        "severity": rec.severity,
        "assessment_digest": rec.assessment_digest,
    }


def _strengthen_payload(rec: "StrengtheningRecord") -> Dict[str, Any]:
    return {
        "strengthening_id": rec.strengthening_id,
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "strategy": rec.strategy,
        "strengthening_digest": rec.strengthening_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "ResilienceReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_assessments": rep.n_assessments,
        "n_resilient": rep.n_resilient,
        "n_at_risk": rep.n_at_risk,
        "n_brittle": rep.n_brittle,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_assessed": rep.n_not_assessed,
        "n_strengthened": rep.n_strengthened,
        "integrity_ok": rep.integrity_ok,
    }


def ai_resilience_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIResilienceError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-resilience",
        "version": AI_RESILIENCE_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIResilience:
    """AI-resilience assessment -> strengthening decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts and
    strengthenings are booked as data - never proof that a system is
    really resilient.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._strengthenings: Dict[str, StrengtheningRecord] = {}
        self._system_assessments: Dict[str, List[str]] = {}
        self._assessment_strengthenings: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._assessment_counter = 0
        self._strengthening_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_resilience_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-resilience",
                "version": AI_RESILIENCE_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_resilience_audit_event(kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def assess(
        self,
        system_id: str,
        seq: int,
        resilience_kind: str = "fault-recovery",
        verdict: str = "not-assessed",
        severity: int = 0,
        assessment_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared resilience assessment (minted ``asm-N`` id).

        The first assessment on an id registers the system. Raw fault
        traces, failover logs, and chaos-run material never enter
        records - digest pins only. Fail-closed: failed mutations consume
        their seq and book an ``ai-resilience.rejected`` row; rewinds
        raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                resilience_kind = _check_resilience_kind(resilience_kind)
                verdict = _check_verdict(verdict)
                severity = _check_severity(severity)
                assessment_digest = _check_digest(assessment_digest, "assessment_digest")
                self._require_live(system_id)
            except AIResilienceError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._assessment_counter += 1
            assessment_id = f"asm-{self._assessment_counter}"
            provisional = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                resilience_kind=resilience_kind,
                verdict=verdict,
                severity=severity,
                assessment_digest=assessment_digest,
                digest="",
            )
            digest = _digest_pin(_assess_payload(provisional), "ai-resilience.assess")
            rec = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                resilience_kind=resilience_kind,
                verdict=verdict,
                severity=severity,
                assessment_digest=assessment_digest,
                digest=digest,
            )
            self._assessments[assessment_id] = rec
            self._system_assessments.setdefault(system_id, []).append(assessment_id)
            self._emit(
                "assessed",
                seq,
                assessment_id=assessment_id,
                system_id=system_id,
                resilience_kind=resilience_kind,
                verdict=verdict,
            )
            return rec

    def strengthen(
        self,
        assessment_id: str,
        seq: int,
        strategy: str = "no-action",
        strengthening_digest: str = "",
    ) -> StrengtheningRecord:
        """Book one declared strengthening against an assessment (``str-N``).

        Repeatable chain (one assessment may have many strengthenings).
        Books the *declaration*, never the deployed fix. Fail-closed on
        unknown assessments and retired systems.
        """
        with self._lock:
            try:
                assessment_id = _check_id(assessment_id, "assessment_id")
                self._require_seq(seq)
                strategy = _check_strategy(strategy)
                strengthening_digest = _check_digest(
                    strengthening_digest, "strengthening_digest"
                )
                if assessment_id not in self._assessments:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}"
                    )
                system_id = self._assessments[assessment_id].system_id
                self._require_live(system_id)
            except AIResilienceError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._strengthening_counter += 1
            strengthening_id = f"str-{self._strengthening_counter}"
            provisional = StrengtheningRecord(
                strengthening_id=strengthening_id,
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                strategy=strategy,
                strengthening_digest=strengthening_digest,
                digest="",
            )
            digest = _digest_pin(
                _strengthen_payload(provisional), "ai-resilience.strengthen"
            )
            rec = StrengtheningRecord(
                strengthening_id=strengthening_id,
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                strategy=strategy,
                strengthening_digest=strengthening_digest,
                digest=digest,
            )
            self._strengthenings[strengthening_id] = rec
            self._assessment_strengthenings.setdefault(assessment_id, []).append(
                strengthening_id
            )
            self._emit(
                "strengthened",
                seq,
                strengthening_id=strengthening_id,
                assessment_id=assessment_id,
                system_id=system_id,
                strategy=strategy,
            )
            return rec

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """**Pure read**: re-derive one assessment or strengthening digest.

        The seq is shape-validated but never consumed and no audit row is
        written. Verdict ``verified`` / ``tampered`` is booked as data;
        tamper is reported, never raised.
        """
        with self._lock:
            seq = _check_seq(seq)
            if record_id in self._assessments:
                rec = self._assessments[record_id]
                payload = _assess_payload(rec)
                tag = "ai-resilience.assess"
            elif record_id in self._strengthenings:
                rec = self._strengthenings[record_id]
                payload = _strengthen_payload(rec)
                tag = "ai-resilience.strengthen"
            else:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            expected = _digest_pin(payload, tag)
            integrity_ok = rec.digest == expected
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict="verified" if integrity_ok else "tampered",
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-resilience.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=provisional.verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> ResilienceReport:
        """**Pure read**: derive one system's resilience posture as data.

        Posture precedence: ``brittle`` (any unstrengthened brittle) ->
        ``uncertain`` (any inconclusive, or any unstrengthened at-risk)
        -> ``unassessed`` (any not-assessed) -> ``strengthened`` (all
        brittle/at-risk covered) -> ``resilient`` (all resilient). The
        seq is shape-validated, never consumed; no audit row is written.
        """
        with self._lock:
            system_id = _check_id(system_id, "system_id")
            seq = _check_seq(seq)
            if system_id not in self._system_assessments:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            ids = self._system_assessments[system_id]
            recs = [self._assessments[i] for i in ids]
            n_assessments = len(recs)
            n_resilient = sum(1 for r in recs if r.verdict == "resilient")
            n_at_risk = sum(1 for r in recs if r.verdict == "at-risk")
            n_brittle = sum(1 for r in recs if r.verdict == "brittle")
            n_inconclusive = sum(1 for r in recs if r.verdict == "inconclusive")
            n_not_assessed = sum(1 for r in recs if r.verdict == "not-assessed")
            strengthened = {
                r.assessment_id for r in recs if self._assessment_strengthenings.get(r.assessment_id)
            }
            n_strengthened = len(strengthened)
            open_brittle = any(
                r.verdict == "brittle" and r.assessment_id not in strengthened
                for r in recs
            )
            open_at_risk = any(
                r.verdict == "at-risk" and r.assessment_id not in strengthened
                for r in recs
            )
            any_inconclusive = any(r.verdict == "inconclusive" for r in recs)
            if open_brittle:
                posture = "brittle"
            elif any_inconclusive or open_at_risk:
                posture = "uncertain"
            elif n_not_assessed > 0:
                posture = "unassessed"
            elif n_brittle > 0 or n_at_risk > 0:
                posture = "strengthened"
            elif n_resilient == n_assessments and n_assessments > 0:
                posture = "resilient"
            else:
                posture = "strengthened"
            integrity_ok = all(
                r.digest == _digest_pin(_assess_payload(r), "ai-resilience.assess")
                for r in recs
            ) and all(
                self._strengthenings[sid].digest
                == _digest_pin(
                    _strengthen_payload(self._strengthenings[sid]),
                    "ai-resilience.strengthen",
                )
                for aid in ids
                for sid in self._assessment_strengthenings.get(aid, [])
            )
            provisional = ResilienceReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=n_assessments,
                n_resilient=n_resilient,
                n_at_risk=n_at_risk,
                n_brittle=n_brittle,
                n_inconclusive=n_inconclusive,
                n_not_assessed=n_not_assessed,
                n_strengthened=n_strengthened,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-resilience.evaluate")
            return ResilienceReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=n_assessments,
                n_resilient=n_resilient,
                n_at_risk=n_at_risk,
                n_brittle=n_brittle,
                n_inconclusive=n_inconclusive,
                n_not_assessed=n_not_assessed,
                n_strengthened=n_strengthened,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a system id. Ids are never recycled.

        Post-retire mutations are refused; reads still work.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_assessments:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                self._require_live(system_id)
            except AIResilienceError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(system_id=system_id, seq=seq, reason=reason, digest="")
            digest = _digest_pin(_retire_payload(provisional), "ai-resilience.retire")
            rec = RetireRecord(system_id=system_id, seq=seq, reason=reason, digest=digest)
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure-read views ---------------------------------------------------

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        seq = _check_seq(seq)
        if assessment_id not in self._assessments:
            raise UnknownAssessmentError(f"unknown assessment: {assessment_id!r}")
        return self._assessments[assessment_id]

    def strengthening_record(self, strengthening_id: str, seq: int) -> StrengtheningRecord:
        seq = _check_seq(seq)
        if strengthening_id not in self._strengthenings:
            raise UnknownRecordError(f"unknown strengthening: {strengthening_id!r}")
        return self._strengthenings[strengthening_id]

    def assessments_for(self, system_id: str, seq: int) -> List[AssessmentRecord]:
        seq = _check_seq(seq)
        if system_id not in self._system_assessments:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        return [self._assessments[i] for i in self._system_assessments[system_id]]

    def strengthenings_for(self, assessment_id: str, seq: int) -> List[StrengtheningRecord]:
        seq = _check_seq(seq)
        if assessment_id not in self._assessments:
            raise UnknownAssessmentError(f"unknown assessment: {assessment_id!r}")
        return [
            self._strengthenings[i]
            for i in self._assessment_strengthenings.get(assessment_id, [])
        ]

    def system_ids(self, seq: int) -> List[str]:
        _check_seq(seq)
        return sorted(self._system_assessments)

    def assessment_ids(self, seq: int) -> List[str]:
        _check_seq(seq)
        return sorted(self._assessments)

    def strengthening_ids(self, seq: int) -> List[str]:
        _check_seq(seq)
        return sorted(self._strengthenings)

    def retired_ids(self, seq: int) -> List[str]:
        _check_seq(seq)
        return sorted(self._retired)

    def stats(self, seq: int) -> Dict[str, Any]:
        _check_seq(seq)
        return {
            "n_assessments": len(self._assessments),
            "n_strengthenings": len(self._strengthenings),
            "n_systems": len(self._system_assessments),
            "n_retired": len(self._retired),
            "seq": self._seq,
        }

    def audit_log(self, seq: int) -> List[Dict[str, Any]]:
        _check_seq(seq)
        return list(self._audit)


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast
    from pathlib import Path

    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: book an assessment, strengthen, verify, and evaluate."""
    led = AIResilience()
    rec = led.assess("sys-1", 1, resilience_kind="failover", verdict="brittle")
    assert rec.assessment_id == "asm-1"
    assert rec.verify()
    st = led.strengthen("asm-1", 2, strategy="failover-drill")
    assert st.strengthening_id == "str-1"
    assert st.verify()
    vr = led.verify("asm-1", 3)
    assert vr.verdict == "verified"
    rep = led.evaluate("sys-1", 4)
    assert rep.posture == "strengthened"
    assert rep.verify()
    assert stdlib_only()
    print("ai-resilience OK: assess, strengthen, verify, evaluate, pins, audit")


if __name__ == "__main__":
    main()
