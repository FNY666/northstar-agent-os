"""AI failure: failure report/analysis decision ledger, Simulated.

Research note: AI failure analysis studies how AI systems fail in
deployment - model-output failures, deployment incidents, safety
violations, security breaches - and what declared analyses say about
their causes. This module is the *decision ledger* for declared AI
failure reports and their declared analyses: which failures were
booked (over a pinned failure-kind vocabulary, with a host-reported
severity), what analyses the host declared against them (over a pinned
analysis-kind vocabulary with declared outcomes), and what failure
posture the ledger derives - defensible bookkeeping, never proof that
a failure was truly resolved.

This module owns the report -> analyze -> evaluate lifecycle:

* **report()** - book one declared failure report (minted ``rpt-N``
  ids; pinned failure-kind vocabulary; host-reported severity int in
  [0, 100]; raw incident material travels as digest pins only); the
  first report registers its system.
* **analyze()** - book one declared analysis against a booked report
  (minted ``anl-N`` ids; pinned analysis-kind vocabulary; pinned
  outcome vocabulary booked *as data*); fail-closed on unknown or
  retired reports; repeatable chain; books the *declaration*, never
  the investigation.
* **verify()** - **pure read**: re-derive one report/analysis record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never
  as proof the failure was analyzed correctly.
* **evaluate()** - **pure read**: derive one system's failure posture
  as data (``unreported`` -> ``critical-open`` -> ``open`` ->
  ``inconclusive`` -> ``mitigated`` -> ``resolved``) with report tallies
  and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_safety.py`` owns the
assessment -> mitigation lifecycle over safety hazard classes;
``ai_audit.py`` owns audit execution; ``ai_oversight.py`` owns
oversight sessions; ``ai_governance.py`` owns governance operations;
``incident_response.py`` owns the operational response lifecycle
(detect -> contain -> eradicate -> recover) - this module is the
failure *reporting/analysis* decision ledger none of them own:
declared failures, declared analyses, digest re-derivation, and the
ledger-rule posture that turns declared outcomes into a resolution
claim, always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-failure.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no incidents,
conducts no investigations, and proves nothing about real failures. A
booked report means "the host declared a failure", never "a failure
really happened"; a booked analysis means "the host declared it",
never "the cause was found"; an ``resolved`` posture is a ledger
derivation, never evidence the failure is fixed. Incident logs, stack
traces, user data, and raw failure material never enter records or
cross the audit boundary - digest pins only.
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
AI_FAILURE_VERSION = "ai-failure.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-failure.v1"

#: Pinned failure-kind vocabulary (the failure classes reported).
FAILURE_KINDS = (
    "model-output-failure",
    "deployment-incident",
    "safety-violation",
    "security-breach",
    "data-corruption",
    "performance-degradation",
    "bias-incident",
    "system-outage",
)

#: Pinned analysis-kind vocabulary (the analysis shapes declared).
ANALYSIS_KINDS = (
    "root-cause-analysis",
    "postmortem",
    "timeline-reconstruction",
    "contributing-factor-analysis",
    "impact-assessment",
    "remediation-plan",
    "recurrence-risk-analysis",
    "reproduction",
)

#: Pinned analysis-outcome vocabulary (booked as data, never proof).
OUTCOMES = (
    "resolved",
    "mitigated",
    "open",
    "wont-fix",
    "inconclusive",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unreported",
    "critical-open",
    "open",
    "inconclusive",
    "mitigated",
    "resolved",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "reported",
    "analyzed",
    "retired",
    "rejected",
)

#: Severity at or above which an unanalyzed report counts as critical.
CRITICAL_SEVERITY = 80

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "incident",
        "incident_log",
        "incident_report",
        "failure_log",
        "stack_trace",
        "stacktrace",
        "traceback",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "telemetry",
        "log",
        "logs",
        "stderr",
        "stdout",
        "command_output",
        "recording",
        "recordings",
        "transcript",
        "transcripts",
        "user_data",
        "personal_data",
        "pii",
        "credentials",
        "password",
        "api_key",
        "token",
        "weights",
        "model_weights",
        "parameters",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "evidence",
        "findings",
        "root_cause_text",
        "analysis_text",
        "notes",
        "narrative",
        "postmortem",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIFailureError(Exception):
    """Base class for all ai-failure ledger errors."""


class BadSystemError(AIFailureError):
    pass


class UnknownSystemError(AIFailureError):
    pass


class RetiredSystemError(AIFailureError):
    pass


class BadFailureKindError(AIFailureError):
    pass


class BadAnalysisKindError(AIFailureError):
    pass


class BadOutcomeError(AIFailureError):
    pass


class BadSeverityError(AIFailureError):
    pass


class BadDigestError(AIFailureError):
    pass


class BadReasonError(AIFailureError):
    pass


class UnknownReportError(AIFailureError):
    pass


class UnknownAnalysisError(AIFailureError):
    pass


class UnknownRecordError(AIFailureError):
    pass


class SeqOrderError(AIFailureError):
    pass


class AuditKindError(AIFailureError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_failure_kind(value: Any) -> str:
    if value not in FAILURE_KINDS:
        raise BadFailureKindError(f"failure_kind must be one of {FAILURE_KINDS}")
    return value


def _check_analysis_kind(value: Any) -> str:
    if value not in ANALYSIS_KINDS:
        raise BadAnalysisKindError(f"analysis_kind must be one of {ANALYSIS_KINDS}")
    return value


def _check_outcome(value: Any) -> str:
    if value not in OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {OUTCOMES}")
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


def _check_read_seq(seq: Any) -> int:
    seq = _check_seq(seq)
    if seq < 0:
        raise SeqOrderError("read seq must be a non-negative int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FailureRecord:
    report_id: str
    system_id: str
    seq: int
    failure_kind: str
    severity: int
    report_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _report_payload(self), "ai-failure.report"
        )


@dataclass(frozen=True)
class AnalysisRecord:
    analysis_id: str
    report_id: str
    system_id: str
    seq: int
    analysis_kind: str
    outcome: str
    analysis_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _analyze_payload(self), "ai-failure.analyze"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-failure.retire"
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
            _verify_payload(self), "ai-failure.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_reports: int
    n_analyzed: int
    n_open: int
    n_critical: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-failure.evaluate"
        )


def _report_payload(rec: "FailureRecord") -> Dict[str, Any]:
    return {
        "report_id": rec.report_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "failure_kind": rec.failure_kind,
        "severity": rec.severity,
        "report_digest": rec.report_digest,
    }


def _analyze_payload(rec: "AnalysisRecord") -> Dict[str, Any]:
    return {
        "analysis_id": rec.analysis_id,
        "report_id": rec.report_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "analysis_kind": rec.analysis_kind,
        "outcome": rec.outcome,
        "analysis_digest": rec.analysis_digest,
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
        "n_reports": rep.n_reports,
        "n_analyzed": rep.n_analyzed,
        "n_open": rep.n_open,
        "n_critical": rep.n_critical,
        "integrity_ok": rep.integrity_ok,
    }


def ai_failure_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIFailureError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-failure",
        "version": AI_FAILURE_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIFailure:
    """AI-failure report/analysis decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All severities, outcomes,
    and postures are booked as data - never proof that a failure was
    really analyzed or resolved.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._reports: Dict[str, FailureRecord] = {}
        self._analyses: Dict[str, AnalysisRecord] = {}
        self._system_reports: Dict[str, List[str]] = {}
        self._report_analyses: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._report_counter = 0
        self._analysis_counter = 0
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
            row = ai_failure_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-failure",
                "version": AI_FAILURE_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_failure_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def report(
        self,
        system_id: str,
        seq: int,
        failure_kind: str = "deployment-incident",
        severity: int = 0,
        report_digest: str = "",
    ) -> FailureRecord:
        """Book one declared failure report (minted ``rpt-N`` id).

        The first report on an id registers the system. Raw incident
        logs, stack traces, and material never enter records - digest
        pins only. Fail-closed: failed mutations consume their seq and
        book an ``ai-failure.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                failure_kind = _check_failure_kind(failure_kind)
                severity = _check_severity(severity)
                report_digest = _check_digest(
                    report_digest, "report_digest"
                )
                self._require_live(system_id)
            except AIFailureError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._report_counter += 1
            report_id = f"rpt-{self._report_counter}"
            provisional = FailureRecord(
                report_id=report_id,
                system_id=system_id,
                seq=seq,
                failure_kind=failure_kind,
                severity=severity,
                report_digest=report_digest,
                digest="",
            )
            digest = _digest_pin(_report_payload(provisional), "ai-failure.report")
            rec = FailureRecord(
                report_id=report_id,
                system_id=system_id,
                seq=seq,
                failure_kind=failure_kind,
                severity=severity,
                report_digest=report_digest,
                digest=digest,
            )
            self._reports[report_id] = rec
            self._system_reports.setdefault(system_id, []).append(report_id)
            self._emit(
                "reported",
                seq,
                report_id=report_id,
                system_id=system_id,
                failure_kind=failure_kind,
                severity=severity,
                report_digest=report_digest,
            )
            return rec

    def analyze(
        self,
        report_id: str,
        seq: int,
        analysis_kind: str = "root-cause-analysis",
        outcome: str = "open",
        analysis_digest: str = "",
    ) -> AnalysisRecord:
        """Book one declared analysis against a booked report.

        Minted ``anl-N`` ids; repeatable chain; fail-closed on unknown
        reports and retired systems. Books the *declaration*, never the
        investigation.
        """
        with self._lock:
            try:
                if (
                    isinstance(report_id, bool)
                    or not isinstance(report_id, str)
                    or report_id not in self._reports
                ):
                    raise UnknownReportError(
                        f"unknown report: {report_id!r}"
                    )
                self._require_seq(seq)
                analysis_kind = _check_analysis_kind(analysis_kind)
                outcome = _check_outcome(outcome)
                analysis_digest = _check_digest(
                    analysis_digest, "analysis_digest"
                )
                system_id = self._reports[report_id].system_id
                self._require_live(system_id)
            except AIFailureError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._analysis_counter += 1
            analysis_id = f"anl-{self._analysis_counter}"
            provisional = AnalysisRecord(
                analysis_id=analysis_id,
                report_id=report_id,
                system_id=system_id,
                seq=seq,
                analysis_kind=analysis_kind,
                outcome=outcome,
                analysis_digest=analysis_digest,
                digest="",
            )
            digest = _digest_pin(_analyze_payload(provisional), "ai-failure.analyze")
            rec = AnalysisRecord(
                analysis_id=analysis_id,
                report_id=report_id,
                system_id=system_id,
                seq=seq,
                analysis_kind=analysis_kind,
                outcome=outcome,
                analysis_digest=analysis_digest,
                digest=digest,
            )
            self._analyses[analysis_id] = rec
            self._report_analyses.setdefault(report_id, []).append(analysis_id)
            self._emit(
                "analyzed",
                seq,
                analysis_id=analysis_id,
                report_id=report_id,
                system_id=system_id,
                analysis_kind=analysis_kind,
                outcome=outcome,
                analysis_digest=analysis_digest,
            )
            return rec

    # -- pure reads --------------------------------------------------------

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one report/analysis record's digest pin.

        Verdict ``verified``/``tampered`` is booked as data (tamper
        reported, never raised). Seq is shape-validated, never consumed,
        and no audit row is written.
        """
        with self._lock:
            seq = _check_read_seq(seq)
            rec = self._reports.get(record_id)
            if rec is None:
                rec = self._analyses.get(record_id)
            if rec is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            if isinstance(rec, FailureRecord):
                payload = _report_payload(rec)
                tag = "ai-failure.report"
            else:
                payload = _analyze_payload(rec)
                tag = "ai-failure.analyze"
            integrity_ok = rec.digest == _digest_pin(payload, tag)
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-failure.verify"
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's failure posture as data.

        Ledger rule with precedence: ``unreported`` (no reports) ->
        ``critical-open`` (any unanalyzed report with severity >= 80) ->
        ``open`` (any unanalyzed report) -> ``inconclusive`` (any
        analysis outcome ``inconclusive``) -> ``mitigated`` (every
        report analyzed; at least one ``mitigated``; none ``open`` or
        ``wont-fix`` or ``inconclusive``) -> ``resolved`` (all reports
        resolved; ``wont-fix`` blocks this posture).
        """
        with self._lock:
            seq = _check_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            report_ids = self._system_reports.get(system_id, [])
            n_reports = len(report_ids)
            analyzed_reports = 0
            n_open = 0
            n_critical = 0
            has_inconclusive = False
            has_open_outcome = False
            has_wont_fix = False
            has_mitigated = False
            all_resolved = True
            integrity_ok = True
            for report_id in report_ids:
                rec = self._reports[report_id]
                if rec.digest != _digest_pin(
                    _report_payload(rec), "ai-failure.report"
                ):
                    integrity_ok = False
                analysis_ids = self._report_analyses.get(report_id, [])
                for analysis_id in analysis_ids:
                    arec = self._analyses[analysis_id]
                    if arec.digest != _digest_pin(
                        _analyze_payload(arec), "ai-failure.analyze"
                    ):
                        integrity_ok = False
                if not analysis_ids:
                    n_open += 1
                    if rec.severity >= CRITICAL_SEVERITY:
                        n_critical += 1
                    all_resolved = False
                    continue
                analyzed_reports += 1
                outcomes = [self._analyses[a].outcome for a in analysis_ids]
                latest = outcomes[-1]
                if latest == "resolved":
                    continue
                all_resolved = False
                if latest == "mitigated":
                    has_mitigated = True
                elif latest == "open":
                    has_open_outcome = True
                elif latest == "wont-fix":
                    has_wont_fix = True
                elif latest == "inconclusive":
                    has_inconclusive = True
            if n_reports == 0:
                posture = "unreported"
            elif n_critical > 0:
                posture = "critical-open"
            elif n_open > 0:
                posture = "open"
            elif has_inconclusive:
                posture = "inconclusive"
            elif has_open_outcome or has_wont_fix:
                posture = "open"
            elif has_mitigated:
                posture = "mitigated"
            elif all_resolved:
                posture = "resolved"
            else:
                posture = "open"
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_reports=n_reports,
                n_analyzed=analyzed_reports,
                n_open=n_open,
                n_critical=n_critical,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-failure.evaluate"
            )
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_reports=n_reports,
                n_analyzed=analyzed_reports,
                n_open=n_open,
                n_critical=n_critical,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_reports:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}"
                    )
            except AIFailureError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-failure.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- views (pure reads) -------------------------------------------------

    def failure_record(self, report_id: str, seq: int) -> FailureRecord:
        with self._lock:
            _check_read_seq(seq)
            rec = self._reports.get(report_id)
            if rec is None:
                raise UnknownReportError(f"unknown report: {report_id!r}")
            return rec

    def analysis_record(self, analysis_id: str, seq: int) -> AnalysisRecord:
        with self._lock:
            _check_read_seq(seq)
            rec = self._analyses.get(analysis_id)
            if rec is None:
                raise UnknownAnalysisError(
                    f"unknown analysis: {analysis_id!r}"
                )
            return rec

    def report_ids(self, seq: int) -> List[str]:
        with self._lock:
            _check_read_seq(seq)
            return sorted(self._reports.keys())

    def analysis_ids(self, seq: int) -> List[str]:
        with self._lock:
            _check_read_seq(seq)
            return sorted(self._analyses.keys())

    def system_ids(self, seq: int) -> List[str]:
        with self._lock:
            _check_read_seq(seq)
            return sorted(self._system_reports.keys())

    def reports_for(self, system_id: str, seq: int) -> List[str]:
        with self._lock:
            _check_read_seq(seq)
            return list(self._system_reports.get(system_id, []))

    def analyses_for(self, report_id: str, seq: int) -> List[str]:
        with self._lock:
            _check_read_seq(seq)
            return list(self._report_analyses.get(report_id, []))

    def retired_ids(self, seq: int) -> List[str]:
        with self._lock:
            _check_read_seq(seq)
            return sorted(self._retired.keys())

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            _check_read_seq(seq)
            return {
                "n_reports": len(self._reports),
                "n_analyses": len(self._analyses),
                "n_systems": len(self._system_reports),
                "n_retired": len(self._retired),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> List[Dict[str, Any]]:
        with self._lock:
            _check_read_seq(seq)
            return list(self._audit)


# ---------------------------------------------------------------------------
# Self-checks
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
    """Self-check: exercise report -> analyze -> verify -> evaluate."""
    ledger = AIFailure()
    assert stdlib_only(), "non-stdlib import detected"
    assert AI_FAILURE_VERSION == "ai-failure.v1"
    assert SCHEMA_PIN == "northstar.ai-failure.v1"
    rec = ledger.report(
        "sys-1",
        1,
        failure_kind="model-output-failure",
        severity=90,
        report_digest="sha256:" + "ab" * 32,
    )
    assert rec.report_id == "rpt-1"
    assert rec.verify()
    anl = ledger.analyze(
        rec.report_id,
        2,
        analysis_kind="root-cause-analysis",
        outcome="open",
    )
    assert anl.analysis_id == "anl-1"
    assert anl.verify()
    rep = ledger.verify(rec.report_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "open"
    anl2 = ledger.analyze(rec.report_id, 5, outcome="resolved")
    assert anl2.verify()
    ev = ledger.evaluate("sys-1", 6)
    assert ev.posture == "resolved"
    ret = ledger.retire("sys-1", 7)
    assert ret.verify()
    print("ai-failure OK: report, analyze, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
