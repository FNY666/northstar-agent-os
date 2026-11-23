"""AI ethics-risk register as a deterministic single-host decision ledger.

Research note: ethics governance separates the *ethics-risk register*
(declared ethics risks against a system: what kind of ethics risk, how
severe, declared as host data) from the declared *ethics controls* (the
governance remedy the host says was applied against which risk). This
module is the bookkeeping layer for that pair: it books declared
ethics-risk assessments over a pinned ethics-risk-kind vocabulary,
declared mitigations over a pinned control-strategy vocabulary,
digest-pinned records, and ledger-rule ethics posture reports. It performs
no risk scoring math beyond booked host-reported severity, runs no probes
or evaluations, and proves nothing about real ethical behavior.

Distinct-layer rationale: ``ai_ethics.py`` owns ethics assessment
workflows; ``ai_safety.py`` owns the AI-safety assessment->mitigation
lifecycle; ``ai_safety_risk.py`` owns the *safety-risk* register
(hierarchy-of-controls mitigations); ``ai_risk.py`` owns the frontier-AI
risk register (misalignment/misuse/power-seeking); this module owns the
*ethics-risk* register: ethics-risk kinds (value misalignment, autonomy
violation, fairness harm, dignity violation), ethics-severity verdicts,
ethics-governance mitigation strategies, and the derived ethics-risk
posture - none of which the others book.

House style: frozen dataclasses, caller int seqs strictly increasing with
claim-then-burn (failed mutations consume their seq + book
``ai-ethics-risk.rejected``; rewinds raise bare without consuming), no
wall-clock, RLock-guarded, fail-closed, stdlib-only + ``canonical_json``
try/except fallback, ``sha256:`` digest pins with ``verify()``,
``audit.ndjson/1`` events.

Honest scope: every verdict, severity, and mitigation is host-declared data.
A booked ``value-alignment`` means "the host declared a value-alignment
control", never that the ethics risk actually went away. ``verify()``
re-derives digest pins; it never proves the ethics risk was truly assessed
or mitigated.
"""

from __future__ import annotations

import ast
import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

try:  # Prefer the in-repo canonicalizer when installed.
    from canonical_json import jcs_sha256_hex, jcs_dumps  # noqa: F401
except Exception:  # pragma: no cover - fallback path
    import json

    def jcs_sha256_hex(obj) -> str:  # noqa: D103
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def jcs_dumps(obj) -> str:  # noqa: D103
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))


#: Module version.
AI_ETHICS_RISK_VERSION = "ai-ethics-risk.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-ethics-risk.v1"

_HASH_DOMAIN = b"northstar.ai-ethics-risk.v1\x00"

#: Pinned ethics-risk-kind vocabulary (ethics-governance taxonomy).
ETHICS_RISK_KINDS = (
    "value-misalignment",
    "autonomy-violation",
    "fairness-harm",
    "privacy-intrusion",
    "dignity-violation",
    "manipulation",
    "accountability-gap",
    "justice-harm",
)

#: Pinned ethics-risk verdict vocabulary (ethics-severity, host-declared, as data).
VERDICTS = (
    "unacceptable",
    "concerning",
    "tolerable",
    "acceptable",
    "not-assessed",
)

#: Pinned mitigation-strategy vocabulary (ethics-governance remedies).
MITIGATION_STRATEGIES = (
    "value-alignment",
    "human-oversight",
    "transparency-disclosure",
    "fairness-audit",
    "consent-mechanism",
    "redress-mechanism",
    "ethics-review",
    "no-action",
)

#: Pinned retire-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "withdrawn",
    "duplicate",
    "superseded",
)

#: Pinned audit kinds.
AUDIT_KINDS = (
    "assessed",
    "mitigated",
    "retired",
    "rejected",
)

#: Pinned posture vocabulary.
POSTURES = (
    "unassessed",
    "unacceptable-open",
    "concerning-open",
    "tolerable-managed",
    "mitigated",
    "acceptable",
)

#: Raw-material keys that may never cross the audit boundary.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "risk",
        "risks",
        "hazard",
        "hazard_analysis",
        "ethics_case",
        "ethics_review",
        "ethics_argument",
        "value_alignment",
        "values",
        "principles",
        "fairness",
        "bias",
        "discrimination",
        "consent",
        "consent_record",
        "redress",
        "redress_case",
        "dignity",
        "autonomy",
        "justice",
        "manipulation",
        "deception",
        "stakeholder",
        "stakeholders",
        "impact_assessment",
        "complaint",
        "grievance",
        "exploit",
        "vulnerability",
        "threat",
        "threat_model",
        "attack",
        "payload",
        "evidence",
        "finding",
        "transcript",
        "trajectory",
        "weights",
        "model_weights",
        "activations",
        "gradient",
        "loss",
        "prompt",
        "response",
        "incident",
        "incident_report",
        "dataset",
        "labels",
        "predictions",
        "demographics",
        "personal_data",
        "pii",
        "password",
        "api_key",
        "secret",
        "credential",
        "score",
        "scores",
        "analysis",
        "report_text",
        "notes",
        "justification",
        "rationale",
        "capability",
        "capabilities",
        "evaluation",
        "test_results",
        "red_team",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIEthicsRiskError(Exception):
    """Base error for the AI ethics-risk ledger."""


class SeqOrderError(AIEthicsRiskError):
    """A seq was not a strictly increasing int, or a rewind was attempted."""


class BadIdError(AIEthicsRiskError):
    """An id was not a usable non-empty string."""


class BadEthicsRiskKindError(AIEthicsRiskError):
    """The ethics-risk kind is outside the pinned vocabulary."""


class BadVerdictError(AIEthicsRiskError):
    """The verdict is outside the pinned vocabulary."""


class BadSeverityError(AIEthicsRiskError):
    """Severity is not a host-reported int in [0, 100]."""


class BadDigestError(AIEthicsRiskError):
    """A digest pin was not a valid ``sha256:`` hex pin (or empty)."""


class UnknownAssessmentError(AIEthicsRiskError):
    """No assessment with that id is booked."""


class UnknownSystemError(AIEthicsRiskError):
    """No system with that id has any booked assessment."""


class RetiredSystemError(AIEthicsRiskError):
    """The system is retired; mutations are refused."""


class BadStrategyError(AIEthicsRiskError):
    """The mitigation strategy is outside the pinned vocabulary."""


class BadReasonError(AIEthicsRiskError):
    """The retire reason is outside the pinned vocabulary."""


class AuditKindError(AIEthicsRiskError):
    """Unknown audit kind."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadIdError(f"{what} must be a non-empty string")
    if len(value) > 256:
        raise BadIdError(f"{what} is too long")
    return value


def _check_ethics_risk_kind(value: Any) -> str:
    if value not in ETHICS_RISK_KINDS:
        raise BadEthicsRiskKindError(f"unknown ethics-risk kind: {value!r}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in VERDICTS:
        raise BadVerdictError(f"unknown verdict: {value!r}")
    return value


def _check_strategy(value: Any) -> str:
    if value not in MITIGATION_STRATEGIES:
        raise BadStrategyError(f"unknown mitigation strategy: {value!r}")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"unknown retire reason: {value!r}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int in [0, 100]")
    if value < 0 or value > 100:
        raise BadSeverityError("severity must be in [0, 100]")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise BadDigestError(f"{what} must be a 'sha256:' pin")
    hexpart = value[len("sha256:"):]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be lowercase hex of length 64")
    return value


def _canonical_bytes(obj: Any) -> bytes:
    raw = jcs_dumps(obj)
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return _HASH_DOMAIN + raw


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


def stdlib_only() -> bool:
    """AST self-check: this module may only import stdlib modules."""
    here = Path(__file__)
    tree = ast.parse(here.read_text(encoding="utf-8"))
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "threading",
        "typing",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    assessment_id: str
    system_id: str
    seq: int
    ethics_risk_kind: str
    verdict: str
    severity: int
    assessment_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_assess_payload(self), "ai-ethics-risk.assess")


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
            _mitigate_payload(self), "ai-ethics-risk.mitigate"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "ai-ethics-risk.retire")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_verify_payload(self), "ai-ethics-risk.verify")


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_assessments: int
    n_unacceptable: int
    n_concerning: int
    n_tolerable: int
    n_acceptable: int
    n_not_assessed: int
    n_mitigated: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-ethics-risk.evaluate"
        )


def _assess_payload(rec: "AssessmentRecord") -> Dict[str, Any]:
    return {
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "ethics_risk_kind": rec.ethics_risk_kind,
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
        "n_unacceptable": rep.n_unacceptable,
        "n_concerning": rep.n_concerning,
        "n_tolerable": rep.n_tolerable,
        "n_acceptable": rep.n_acceptable,
        "n_not_assessed": rep.n_not_assessed,
        "n_mitigated": rep.n_mitigated,
        "integrity_ok": rep.integrity_ok,
    }


def ai_ethics_risk_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIEthicsRiskError(f"raw key {key!r} may not cross the audit boundary")
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-ethics-risk",
        "version": AI_ETHICS_RISK_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIEthicsRisk:
    """AI ethics-risk register decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts, severities, and
    mitigations are booked as data - never proof that an ethics risk was
    truly assessed or mitigated.
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
        _check_seq(seq)
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
            row = ai_ethics_risk_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-ethics-risk",
                "version": AI_ETHICS_RISK_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_ethics_risk_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    def _require_read_seq(self, seq: Any) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("read seq must be a non-negative int")

    # -- mutations ---------------------------------------------------------

    def assess(
        self,
        system_id: str,
        seq: int,
        ethics_risk_kind: str = "value-misalignment",
        verdict: str = "not-assessed",
        severity: int = 0,
        assessment_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared ethics-risk assessment (minted ``erk-N`` id).

        The first assessment on an id registers the system. Raw ethics
        material never enters records - digest pins only. Fail-closed:
        failed mutations consume their seq and book an
        ``ai-ethics-risk.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                _check_seq(seq)
                if seq <= self._seq:
                    raise SeqOrderError("seq must strictly increase")
                ethics_risk_kind = _check_ethics_risk_kind(ethics_risk_kind)
                verdict = _check_verdict(verdict)
                severity = _check_severity(severity)
                assessment_digest = _check_digest(assessment_digest, "assessment_digest")
                self._require_live(system_id)
            except AIEthicsRiskError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._assessment_counter += 1
            assessment_id = f"erk-{self._assessment_counter}"
            provisional = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                ethics_risk_kind=ethics_risk_kind,
                verdict=verdict,
                severity=severity,
                assessment_digest=assessment_digest,
                digest="",
            )
            digest = _digest_pin(_assess_payload(provisional), "ai-ethics-risk.assess")
            rec = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                ethics_risk_kind=ethics_risk_kind,
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
                ethics_risk_kind=ethics_risk_kind,
                verdict=verdict,
            )
            return rec

    def mitigate(
        self,
        assessment_id: str,
        seq: int,
        strategy: str = "value-alignment",
        mitigation_digest: str = "",
    ) -> MitigationRecord:
        """Book one declared mitigation against an assessment (``mit-N``).

        Mitigations are chainable: an assessment may carry several declared
        mitigations. Fail-closed on unknown assessments and retired systems.
        """
        with self._lock:
            try:
                assessment_id = _check_id(assessment_id, "assessment_id")
                _check_seq(seq)
                if seq <= self._seq:
                    raise SeqOrderError("seq must strictly increase")
                strategy = _check_strategy(strategy)
                mitigation_digest = _check_digest(mitigation_digest, "mitigation_digest")
                assessment = self._assessments.get(assessment_id)
                if assessment is None:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}"
                    )
                system_id = assessment.system_id
                self._require_live(system_id)
            except AIEthicsRiskError as exc:
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
                system_id=system_id,
                seq=seq,
                strategy=strategy,
                mitigation_digest=mitigation_digest,
                digest="",
            )
            digest = _digest_pin(_mitigate_payload(provisional), "ai-ethics-risk.mitigate")
            rec = MitigationRecord(
                mitigation_id=mitigation_id,
                assessment_id=assessment_id,
                system_id=system_id,
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
                system_id=system_id,
                strategy=strategy,
            )
            return rec

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminal: retire a system. Ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                _check_seq(seq)
                if seq <= self._seq:
                    raise SeqOrderError("seq must strictly increase")
                reason = _check_reason(reason)
                if system_id not in self._system_assessments:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIEthicsRiskError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-ethics-risk.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads ----------------------------------------------------------

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Re-derive the digest pin of an assessment or mitigation record.

        Pure read: the seq is shape-validated but never consumed and no audit
        row is written. Verdict is data (``verified``/``tampered``) - tamper
        is reported, never raised.
        """
        with self._lock:
            self._require_read_seq(seq)
            record_id = _check_id(record_id, "record_id")
            rec = self._assessments.get(record_id)
            if rec is not None:
                ok = rec.verify()
            else:
                rec = self._mitigations.get(record_id)
                if rec is None:
                    raise UnknownAssessmentError(f"unknown record: {record_id!r}")
                ok = rec.verify()
            verdict = "verified" if ok else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-ethics-risk.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Derive the ledger-rule ethics-risk posture for a system. Pure read."""
        with self._lock:
            self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_assessments:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            assessments = [
                self._assessments[aid] for aid in self._system_assessments[system_id]
            ]
            n_unacceptable = n_concerning = n_tolerable = n_acceptable = 0
            n_not_assessed = n_mitigated = 0
            integrity_ok = True
            open_unacceptable = open_concerning = open_unknown = False
            for rec in assessments:
                if not rec.verify():
                    integrity_ok = False
                verdict = rec.verdict
                if verdict == "unacceptable":
                    n_unacceptable += 1
                elif verdict == "concerning":
                    n_concerning += 1
                elif verdict == "tolerable":
                    n_tolerable += 1
                elif verdict == "acceptable":
                    n_acceptable += 1
                else:
                    n_not_assessed += 1
                if self._assessment_mitigations.get(rec.assessment_id):
                    n_mitigated += 1
                elif verdict == "unacceptable":
                    open_unacceptable = True
                elif verdict == "concerning":
                    open_concerning = True
                elif verdict in ("tolerable", "not-assessed"):
                    open_unknown = True
            for mid_list in self._assessment_mitigations.values():
                for mid in mid_list:
                    if not self._mitigations[mid].verify():
                        integrity_ok = False
            if not assessments:
                posture = "unassessed"
            elif open_unacceptable:
                posture = "unacceptable-open"
            elif open_concerning:
                posture = "concerning-open"
            elif open_unknown:
                posture = "tolerable-managed"
            elif n_mitigated == len(assessments):
                posture = "mitigated"
            else:
                # Only unmitigated acceptable risks remain.
                posture = "acceptable"
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(assessments),
                n_unacceptable=n_unacceptable,
                n_concerning=n_concerning,
                n_tolerable=n_tolerable,
                n_acceptable=n_acceptable,
                n_not_assessed=n_not_assessed,
                n_mitigated=n_mitigated,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-ethics-risk.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(assessments),
                n_unacceptable=n_unacceptable,
                n_concerning=n_concerning,
                n_tolerable=n_tolerable,
                n_acceptable=n_acceptable,
                n_not_assessed=n_not_assessed,
                n_mitigated=n_mitigated,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views ------------------------------------------------------

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._assessments.get(_check_id(assessment_id, "assessment_id"))
            if rec is None:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}"
                )
            return rec

    def mitigation_record(self, mitigation_id: str, seq: int) -> MitigationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._mitigations.get(_check_id(mitigation_id, "mitigation_id"))
            if rec is None:
                raise UnknownAssessmentError(f"unknown mitigation: {mitigation_id!r}")
            return rec

    def assessments_for(self, system_id: str, seq: int) -> List[AssessmentRecord]:
        with self._lock:
            self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            return [
                self._assessments[aid]
                for aid in self._system_assessments.get(system_id, [])
            ]

    def mitigations_for(self, assessment_id: str, seq: int) -> List[MitigationRecord]:
        with self._lock:
            self._require_read_seq(seq)
            assessment_id = _check_id(assessment_id, "assessment_id")
            return [
                self._mitigations[mid]
                for mid in self._assessment_mitigations.get(assessment_id, [])
            ]

    def system_ids(self, seq: int) -> List[str]:
        with self._lock:
            self._require_read_seq(seq)
            return sorted(self._system_assessments)

    def assessment_ids(self, seq: int) -> List[str]:
        with self._lock:
            self._require_read_seq(seq)
            return sorted(self._assessments)

    def mitigation_ids(self, seq: int) -> List[str]:
        with self._lock:
            self._require_read_seq(seq)
            return sorted(self._mitigations)

    def retired_ids(self, seq: int) -> List[str]:
        with self._lock:
            self._require_read_seq(seq)
            return sorted(self._retired)

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_systems": len(self._system_assessments),
                "n_assessments": len(self._assessments),
                "n_mitigations": len(self._mitigations),
                "n_retired": len(self._retired),
                "n_rejected": sum(
                    1 for row in self._audit if row.get("kind") == "rejected"
                ),
            }

    def audit_log(self, seq: int) -> List[Dict[str, Any]]:
        with self._lock:
            self._require_read_seq(seq)
            return [dict(row) for row in self._audit]


def main() -> None:
    ledger = AIEthicsRisk()
    rec = ledger.assess(
        "sys-1", 1, ethics_risk_kind="fairness-harm", verdict="unacceptable",
        severity=95,
    )
    assert rec.verify()
    mit = ledger.mitigate(rec.assessment_id, 2, strategy="fairness-audit")
    assert mit.verify()
    report = ledger.evaluate("sys-1", 3)
    assert report.posture == "mitigated", report.posture
    v = ledger.verify(rec.assessment_id, 3)
    assert v.verdict == "verified"
    assert stdlib_only()
    print("ai-ethics-risk OK: assess, mitigate, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
