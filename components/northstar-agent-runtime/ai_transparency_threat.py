"""AI transparency threat: transparency-threat assessment/mitigation decision ledger, Simulated.

Research note: AI transparency threats are hazards that threaten the
*transparency* posture of an AI system or its deployment - active perils
such as model opacity, decision opacity, explanation gaps, disclosure
failures, audit-trail gaps, provenance gaps, interpretability deficits,
and oversight blindness. Unlike ``ai_threat.py`` (which covers
*offensive* AI-capability threats - AI as a weapon),
``ai_safety_threat.py`` (which covers threats against the *safety*
posture), ``ai_ethics_threat.py`` (which covers threats against the
*ethical* posture), and ``ai_fairness_threat.py`` (which covers threats
against the *fairness* posture), this module is the
*transparency-threat* decision ledger: declared transparency-threat
assessments against systems (over a pinned transparency-threat
vocabulary), declared mitigations the host books against them, and the
ledger-rule posture derived from the declared verdicts - defensible
bookkeeping, never proof that a real transparency threat exists or is
contained.

This module owns the assess -> mitigate -> evaluate lifecycle:

* **assess()** - book one declared transparency-threat assessment
  (minted ``asm-N`` ids; pinned transparency-threat-kind vocabulary;
  pinned verdict vocabulary booked *as data*); the first assessment
  registers its system; raw transparency material, explanation
  evidence, complaint material, and assessment evidence never enter
  records - digest pins only.
* **mitigate()** - book one declared mitigation against a booked
  assessment (minted ``mit-N`` ids; pinned mitigation-strategy
  vocabulary booked *as data*); repeatable chain; books the
  *declaration*, never the deployed fix.
* **verify()** - **pure read**: re-derive one assessment/mitigation
  record's digest pin; verdict ``verified`` / ``tampered`` booked as
  data, never as proof the assessment really happened.
* **evaluate()** - **pure read**: derive one system's
  transparency-threat posture as data (``unassessed`` -> ``threatening``
  -> ``suspect`` -> ``mitigated`` -> ``contained``) with verdict tallies
  and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_transparency.py`` owns the
broad transparency assessment->mitigation lifecycle (declared
disclosure, explainability, and auditability targets); this module owns
the *threat declaration* ledger (active transparency perils - model
opacity, explanation gaps, audit-trail gaps - declared as threats
*against* the transparency posture, with declared verdicts and declared
mitigations); ``ai_threat.py`` owns *offensive-capability* threat
assessments (AI as the weapon); ``ai_safety_threat.py``,
``ai_ethics_threat.py``, and ``ai_fairness_threat.py`` own threats
against the *safety*, *ethical*, and *fairness* postures - this module
owns threats against the *transparency* posture; incident-lifecycle
siblings own post-hoc report->investigate lifecycles - threats are
pre-incident declarations; detector mechanics modules own detection
runs, not the declaration ledger.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-transparency-threat.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no monitoring, deploys no mitigations,
and proves nothing about real AI transparency threats. A booked
``active`` verdict means "the host declared it", never "the threat is
real"; a booked mitigation means "the host declared it", never "the
threat is gone". Transparency material, explanation evidence, complaint
material, and raw assessment evidence never enter records or cross the
audit boundary - digest pins only.
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_TRANSPARENCY_THREAT_VERSION = "ai-transparency-threat.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-transparency-threat.v1"

#: Pinned transparency-threat-kind vocabulary (threats against AI transparency).
TRANSPARENCY_THREAT_KINDS = (
    "model-opacity",
    "decision-opacity",
    "explanation-gap",
    "audit-trail-gap",
    "provenance-gap",
    "disclosure-failure",
    "interpretability-deficit",
    "oversight-blindness",
)

#: Pinned assessment-verdict vocabulary (booked as data, never proof).
ASSESS_VERDICTS = (
    "active",
    "suspected",
    "contained",
    "inconclusive",
    "not-assessed",
)

#: Pinned mitigation-strategy vocabulary (booked as data, never proof).
MITIGATION_STRATEGIES = (
    "transparency-report",
    "explanation-provision",
    "disclosure-update",
    "audit-trail-repair",
    "provenance-tracking",
    "interpretability-tooling",
    "oversight-escalation",
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
    "threatening",
    "suspect",
    "mitigated",
    "contained",
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
    "mitigated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        # transparency-specific raw material
        "model_card",
        "model_cards",
        "system_card",
        "system_cards",
        "data_sheet",
        "datasheet",
        "decision_log",
        "decision_logs",
        "explanation_trace",
        "explanation_traces",
        "saliency_map",
        "saliency_maps",
        "feature_attribution",
        "attention_weights",
        "provenance_record",
        "lineage_record",
        "training_provenance",
        "evaluation_provenance",
        "audit_trail",
        "audit_logs",
        "disclosure_document",
        "disclosure_text",
        "transparency_report",
        "transparency_assessment",
        "opacity_analysis",
        "black_box_reasoning",
        "internal_deliberation",
        "review_minutes",
        "board_notes",
        "oversight_note",
        "auditor_identity",
        "reviewer_identity",
        "watcher_identity",
        "whistleblower",
        "complaint_text",
        "complaint",
        "complainant",
        "complainant_identity",
        "grievance",
        "grievances",
        # standard internal-assessment raw material
        "reasoning",
        "reasoning_trace",
        "chain_of_thought",
        "cot",
        "internal_monologue",
        "hidden_state",
        "activations",
        "logits",
        "gradients",
        "weights",
        "model_weights",
        "telemetry",
        "safety_telemetry",
        "behavior_log",
        "behavior_trace",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "deception_evidence",
        "misalignment_evidence",
        "scheming",
        "exfiltration_plan",
        "replication_plan",
        "escape_plan",
        "self_modification",
        "weights_exfil",
        "prompt",
        "prompts",
        "response",
        "responses",
        "recording",
        "recordings",
        "log",
        "logs",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "observation",
        "observations",
        "sensor",
        "sensor_data",
        "metrics",
        "trace",
        "traces",
        "evidence",
        "forensic",
        "forensics",
        "incident_report",
        "harm_narrative",
        "threat_intel",
        "intelligence",
        "credentials",
        "credential",
        "password",
        "passwords",
        "api_key",
        "secret_key",
        "private_key",
        "token",
        "session_token",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AITransparencyThreatError(Exception):
    """Base class for all ai-transparency-threat ledger errors."""


class BadSystemError(AITransparencyThreatError):
    pass


class UnknownSystemError(AITransparencyThreatError):
    pass


class RetiredSystemError(AITransparencyThreatError):
    pass


class BadTransparencyThreatKindError(AITransparencyThreatError):
    pass


class BadVerdictError(AITransparencyThreatError):
    pass


class BadSeverityError(AITransparencyThreatError):
    pass


class BadDigestError(AITransparencyThreatError):
    pass


class BadReasonError(AITransparencyThreatError):
    pass


class UnknownAssessmentError(AITransparencyThreatError):
    pass


class UnknownMitigationError(AITransparencyThreatError):
    pass


class UnknownRecordError(AITransparencyThreatError):
    pass


class BadStrategyError(AITransparencyThreatError):
    pass


class SeqOrderError(AITransparencyThreatError):
    pass


class AuditKindError(AITransparencyThreatError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_transparency_threat_kind(value: Any) -> str:
    if value not in TRANSPARENCY_THREAT_KINDS:
        raise BadTransparencyThreatKindError(
            f"transparency_threat_kind must be one of {TRANSPARENCY_THREAT_KINDS}"
        )
    return value


def _check_verdict(value: Any) -> str:
    if value not in ASSESS_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {ASSESS_VERDICTS}")
    return value


def _check_strategy(value: Any) -> str:
    if value not in MITIGATION_STRATEGIES:
        raise BadStrategyError(f"strategy must be one of {MITIGATION_STRATEGIES}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int")
    if not 0 <= value <= 100:
        raise BadSeverityError("severity must be in [0, 100]")
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
    transparency_threat_kind: str
    verdict: str
    severity: int
    assessment_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _assess_payload(self), "ai-transparency-threat.assess"
        )


@dataclass(frozen=True)
class MitigationRecord:
    mitigation_id: str
    assessment_id: str
    system_id: str
    seq: int
    strategy: str
    mitigation_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _mitigate_payload(self), "ai-transparency-threat.mitigate"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-transparency-threat.retire"
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-transparency-threat.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_assessments: int
    n_threatening: int
    n_suspected: int
    n_contained: int
    n_inconclusive: int
    n_not_assessed: int
    n_mitigated: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-transparency-threat.evaluate"
        )


def _assess_payload(rec: "AssessmentRecord") -> Dict[str, Any]:
    return {
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "transparency_threat_kind": rec.transparency_threat_kind,
        "verdict": rec.verdict,
        "severity": rec.severity,
        "assessment_digest": rec.assessment_digest,
    }


def _mitigate_payload(rec: "MitigationRecord") -> Dict[str, Any]:
    return {
        "mitigation_id": rec.mitigation_id,
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "strategy": rec.strategy,
        "mitigation_digest": rec.mitigation_digest,
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


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_assessments": rep.n_assessments,
        "n_threatening": rep.n_threatening,
        "n_suspected": rep.n_suspected,
        "n_contained": rep.n_contained,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_assessed": rep.n_not_assessed,
        "n_mitigated": rep.n_mitigated,
        "integrity_ok": rep.integrity_ok,
    }


def ai_transparency_threat_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AITransparencyThreatError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-transparency-threat",
        "version": AI_TRANSPARENCY_THREAT_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AITransparencyThreat:
    """AI-transparency-threat assessment/mitigation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts and mitigations
    are booked as data - never proof that a transparency threat is real or
    contained.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._system_assessments: Dict[str, List[str]] = {}
        self._assessment_mitigations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._assessment_counter = 0
        self._mitigation_counter = 0
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
            row = ai_transparency_threat_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-transparency-threat",
                "version": AI_TRANSPARENCY_THREAT_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_transparency_threat_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def assess(
        self,
        system_id: str,
        seq: int,
        transparency_threat_kind: str = "model-opacity",
        verdict: str = "not-assessed",
        severity: int = 0,
        assessment_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared transparency-threat assessment (minted ``asm-N`` id).

        The first assessment on an id registers the system. Raw transparency
        material, explanation evidence, complaint material, and assessment
        evidence never enter records - digest pins only. Fail-closed: failed
        mutations consume their seq and book an
        ``ai-transparency-threat.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                transparency_threat_kind = _check_transparency_threat_kind(transparency_threat_kind)
                verdict = _check_verdict(verdict)
                severity = _check_severity(severity)
                assessment_digest = _check_digest(
                    assessment_digest, "assessment_digest"
                )
                self._require_live(system_id)
            except AITransparencyThreatError as exc:
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
                transparency_threat_kind=transparency_threat_kind,
                verdict=verdict,
                severity=severity,
                assessment_digest=assessment_digest,
                digest="",
            )
            digest = _digest_pin(
                _assess_payload(provisional), "ai-transparency-threat.assess"
            )
            rec = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                transparency_threat_kind=transparency_threat_kind,
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
                transparency_threat_kind=transparency_threat_kind,
                verdict=verdict,
                severity=severity,
            )
            return rec

    def mitigate(
        self,
        assessment_id: str,
        seq: int,
        strategy: str = "no-action",
        mitigation_digest: str = "",
    ) -> MitigationRecord:
        """Book one declared mitigation against a booked assessment (minted ``mit-N`` id).

        Books the *declaration*, never the deployed fix. Repeatable as a
        chain. Fail-closed: failed mutations consume their seq and book
        an ``ai-transparency-threat.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                assessment_id = _check_id(assessment_id, "assessment_id")
                self._require_seq(seq)
                strategy = _check_strategy(strategy)
                mitigation_digest = _check_digest(
                    mitigation_digest, "mitigation_digest"
                )
                assessment = self._assessments.get(assessment_id)
                if assessment is None:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}"
                    )
                self._require_live(assessment.system_id)
            except AITransparencyThreatError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._mitigation_counter += 1
            mitigation_id = f"mit-{self._mitigation_counter}"
            provisional = MitigationRecord(
                mitigation_id=mitigation_id,
                assessment_id=assessment_id,
                system_id=assessment.system_id,
                seq=seq,
                strategy=strategy,
                mitigation_digest=mitigation_digest,
                digest="",
            )
            digest = _digest_pin(
                _mitigate_payload(provisional), "ai-transparency-threat.mitigate"
            )
            rec = MitigationRecord(
                mitigation_id=mitigation_id,
                assessment_id=assessment_id,
                system_id=assessment.system_id,
                seq=seq,
                strategy=strategy,
                mitigation_digest=mitigation_digest,
                digest=digest,
            )
            self._mitigations[mitigation_id] = rec
            self._assessment_mitigations.setdefault(assessment_id, []).append(
                mitigation_id
            )
            self._emit(
                "mitigated",
                seq,
                mitigation_id=mitigation_id,
                assessment_id=assessment_id,
                system_id=assessment.system_id,
                strategy=strategy,
            )
            return rec

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_assessments:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AITransparencyThreatError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-transparency-threat.retire"
            )
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads ----------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        return seq

    def _integrity_ok(self, system_id: str) -> bool:
        return all(
            self._assessments[aid].verify()
            and all(
                self._mitigations[mid].verify()
                for mid in self._assessment_mitigations.get(aid, [])
            )
            for aid in self._system_assessments.get(system_id, [])
        )

    def _posture(self, system_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "threatening": 0,
            "suspected": 0,
            "contained": 0,
            "inconclusive": 0,
            "not-assessed": 0,
            "mitigated": 0,
        }
        ids = self._system_assessments.get(system_id, [])
        for aid in ids:
            rec = self._assessments[aid]
            if rec.verdict == "active":
                tallies["threatening"] += 1
            else:
                tallies[rec.verdict] += 1
            if self._assessment_mitigations.get(aid):
                tallies["mitigated"] += 1
        if not ids:
            return "unassessed", tallies
        if any(
            self._assessments[aid].verdict == "active"
            and not self._assessment_mitigations.get(aid)
            for aid in ids
        ):
            return "threatening", tallies
        if tallies["suspected"] or tallies["inconclusive"]:
            return "suspect", tallies
        if tallies["threatening"]:
            return "mitigated", tallies
        if all(self._assessments[aid].verdict == "contained" for aid in ids):
            return "contained", tallies
        return "suspect", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._assessments.get(record_id) or self._mitigations.get(record_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-transparency-threat.verify"
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's transparency-threat posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_assessments:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            posture, tallies = self._posture(system_id)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(self._system_assessments[system_id]),
                n_threatening=tallies["threatening"],
                n_suspected=tallies["suspected"],
                n_contained=tallies["contained"],
                n_inconclusive=tallies["inconclusive"],
                n_not_assessed=tallies["not-assessed"],
                n_mitigated=tallies["mitigated"],
                integrity_ok=self._integrity_ok(system_id),
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-transparency-threat.evaluate"
            )
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(self._system_assessments[system_id]),
                n_threatening=tallies["threatening"],
                n_suspected=tallies["suspected"],
                n_contained=tallies["contained"],
                n_inconclusive=tallies["inconclusive"],
                n_not_assessed=tallies["not-assessed"],
                n_mitigated=tallies["mitigated"],
                integrity_ok=self._integrity_ok(system_id),
                digest=digest,
            )

    # -- views (pure reads) ----------------------------------------------------

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._assessments.get(assessment_id)
            if rec is None:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}"
                )
            return rec

    def mitigation_record(self, mitigation_id: str, seq: int) -> MitigationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._mitigations.get(mitigation_id)
            if rec is None:
                raise UnknownMitigationError(
                    f"unknown mitigation: {mitigation_id!r}"
                )
            return rec

    def assessments_for(self, system_id: str, seq: int) -> Tuple[AssessmentRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._assessments[aid]
                for aid in self._system_assessments.get(system_id, [])
            )

    def mitigations_for(
        self, assessment_id: str, seq: int
    ) -> Tuple[MitigationRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._mitigations[mid]
                for mid in self._assessment_mitigations.get(assessment_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._system_assessments.keys()))

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._assessments.keys()))

    def mitigation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._mitigations.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_assessments),
                "n_assessments": len(self._assessments),
                "n_mitigations": len(self._mitigations),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# stdlib self-check and CLI
# ---------------------------------------------------------------------------


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
    """Self-check: exercise assess -> mitigate -> verify -> evaluate."""
    ledger = AITransparencyThreat()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.assess(
        "sys-1",
        1,
        transparency_threat_kind="decision-opacity",
        verdict="active",
        severity=80,
    )
    assert rec.verify()
    mit = ledger.mitigate(rec.assessment_id, 2, strategy="provenance-tracking")
    assert mit.verify()
    rep = ledger.verify(rec.assessment_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "mitigated"
    ret = ledger.retire("sys-1", 5)
    assert ret.verify()
    print("ai-transparency-threat OK: assess, mitigate, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
