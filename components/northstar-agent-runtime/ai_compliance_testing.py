"""AI compliance testing: declared compliance-test-execution decision ledger, Simulated.

Research note: AI compliance testing is the compliance-specific
complement of general AI testing - declared executions of declared
*compliance* tests (regulatory-compliance tests, policy-compliance
tests, standards-conformance tests, legal-requirement tests,
contractual-obligation tests, audit-trail-completeness tests,
disclosure-obligation tests, compliance-reporting tests) against
declared AI systems, with declared outcomes (passed, failed, partial,
inconclusive, not-run). This module is the *decision ledger* for
declared compliance test runs: which systems had which compliance test
runs booked (over a pinned compliance-test-kind vocabulary and a pinned
outcome vocabulary), what outcomes were declared, and what
compliance-test posture the ledger derives - defensible bookkeeping,
never proof that any system was really compliance-tested.

This module owns the test -> verify -> evaluate lifecycle:

* **test()** - book one declared compliance test execution run
  (minted ``cpt-N`` ids; pinned compliance-test-kind and outcome
  vocabularies booked *as data*); the first run on an id registers the
  system; raw compliance-test material, regulatory filings, auditor
  workpapers, corrective-action records, control evidence, and raw
  execution traces never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one compliance test
  record's digest pin; verdict ``verified`` / ``tampered`` booked as
  data, never as proof the test really ran.
* **evaluate()** - **pure read**: derive one system's
  compliance-test posture as data (``untested`` -> ``failing`` ->
  ``inconclusive`` -> ``partially-tested`` -> ``passed``) with outcome
  tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_testing.py`` owns declared
*general* test executions (unit/integration/eval-suite); the
safety-test ledger (``ai_safety_testing.py``) owns declared
*safety*-test executions; the ethics-test ledger
(``ai_ethics_testing.py``) owns declared *ethics*-test executions; the
fairness-test ledger (``ai_fairness_testing.py``) owns declared
*fairness*-test executions; the transparency-test ledger
(``ai_transparency_testing.py``) owns declared *transparency*-test
executions; the accountability-test ledger
(``ai_accountability_testing.py``) owns declared *accountability*-test
executions; the oversight-test ledger (``ai_oversight_testing.py``)
owns declared *oversight*-test executions; ``ai_compliance.py`` owns
the *compliance* assessment lifecycle (assess -> mitigate -> evaluate),
``ai_compliance_auditing.py`` owns compliance-audit executions - this
module is the *compliance-test* execution ledger none of them own:
declared per-run compliance-test executions of declared systems
against a pinned compliance-test-kind vocabulary, digest
re-derivation of those runs, and the ledger-rule posture that turns
declared runs into a compliance-test claim, always as data, never as
measured compliance.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-compliance-testing.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs nothing, tests nothing, and proves
nothing about real-world system compliance. A booked ``passed``
posture means "the host declared it", never "the system is
compliant"; a booked ``failed`` outcome means "the host
declared it", never "the system truly failed a compliance test".
Regulatory filings, auditor workpapers, corrective-action records,
control evidence, obligation matrices, requirement traceability,
training records, attestation letters, and raw execution traces
never enter records or cross the audit boundary - digest pins only.
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
AI_COMPLIANCE_TESTING_VERSION = "ai-compliance-testing.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-compliance-testing.v1"

#: Pinned compliance-test-kind vocabulary (the kinds of declared compliance test runs).
COMPLIANCE_TEST_KINDS = (
    "regulatory-compliance-test",
    "policy-compliance-test",
    "standards-conformance-test",
    "legal-requirement-test",
    "contractual-obligation-test",
    "audit-trail-completeness-test",
    "disclosure-obligation-test",
    "compliance-reporting-test",
)

#: Pinned test-outcome vocabulary (booked as data, never proof).
COMPLIANCE_TEST_OUTCOMES = (
    "passed",
    "failed",
    "partial",
    "inconclusive",
    "not-run",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "untested",
    "failing",
    "inconclusive",
    "partially-tested",
    "passed",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "tested",
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
        "checkpoint",
        "checkpoints",
        "backup",
        "backups",
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
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "evidence",
        "findings",
        "report",
        "reports",
        "postmortem",
        "root_cause",
        "harm",
        "harm_description",
        "damage",
        "damages",
        "remedy_text",
        "password",
        "passwords",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "api_key",
        "api_keys",
        "token",
        "tokens",
        "private_key",
        "personal_data",
        "personal_information",
        "identity",
        "identity_document",
        "document",
        "documents",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "dataset",
        "datasets",
        "training_data",
        "pii",
        "exploit",
        "exploits",
        "payload",
        "vulnerability_detail",
        # compliance-testing-specific raw material
        "compliance_case",
        "compliance_cases",
        "compliance_report",
        "compliance_reports",
        "compliance_audit_material",
        "compliance_record",
        "compliance_records",
        "compliance_log",
        "compliance_logs",
        "compliance_plan",
        "compliance_playbook",
        "compliance_committee",
        "compliance_panel",
        "regulator_identity",
        "auditor_identity",
        "auditee_identity",
        "reviewer_identity",
        "monitor_identity",
        "operator_identity",
        "oncall_identity",
        "regulatory_filing",
        "regulatory_filings",
        "regulatory_report",
        "regulatory_reports",
        "regulatory_correspondence",
        "regulatory_submission",
        "audit_finding",
        "audit_findings",
        "audit_workpaper",
        "audit_workpapers",
        "corrective_action",
        "corrective_actions",
        "corrective_action_plan",
        "control_evidence",
        "control_test_result",
        "control_test_results",
        "control_deficiency",
        "control_deficiencies",
        "obligation_matrix",
        "requirement_traceability",
        "gap_analysis",
        "gap_assessment",
        "attestation_letter",
        "attestation_letters",
        "sop_document",
        "sop_documents",
        "policy_manual",
        "policy_manuals",
        "training_record",
        "training_records",
        "certification_record",
        "certification_records",
        "license_document",
        "license_documents",
        "permit_document",
        "permit_documents",
        "legal_opinion",
        "legal_opinions",
        "contract_document",
        "contract_documents",
        "disclosure_filing",
        "filing_receipt",
        "remediation_evidence",
        "exception_approval",
        "waiver_request",
        "enforcement_action",
        "penalty_record",
        "sanction_record",
        "violation_notice",
        "test_data",
        "test_case",
        "test_cases",
        "answers",
        "answer_key",
        "labels",
        "predictions",
        "score_details",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIComplianceTestingError(Exception):
    """Base class for all ai-compliance-testing ledger errors."""


class BadSystemError(AIComplianceTestingError):
    pass


class UnknownSystemError(AIComplianceTestingError):
    pass


class RetiredSystemError(AIComplianceTestingError):
    pass


class BadComplianceTestKindError(AIComplianceTestingError):
    pass


class BadOutcomeError(AIComplianceTestingError):
    pass


class BadDigestError(AIComplianceTestingError):
    pass


class BadReasonError(AIComplianceTestingError):
    pass


class UnknownComplianceTestError(AIComplianceTestingError):
    pass


class SeqOrderError(AIComplianceTestingError):
    pass


class AuditKindError(AIComplianceTestingError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_compliance_test_kind(value: Any) -> str:
    if value not in COMPLIANCE_TEST_KINDS:
        raise BadComplianceTestKindError(
            f"compliance_test_kind must be one of {COMPLIANCE_TEST_KINDS}"
        )
    return value


def _check_outcome(value: Any) -> str:
    if value not in COMPLIANCE_TEST_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {COMPLIANCE_TEST_OUTCOMES}")
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


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ComplianceTestRecord:
    test_id: str
    system_id: str
    seq: int
    compliance_test_kind: str
    outcome: str
    test_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _compliance_test_payload(self), "ai-compliance-testing.test"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-compliance-testing.retire"
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
            _verify_payload(self), "ai-compliance-testing.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_runs: int
    n_passed: int
    n_failed: int
    n_partial: int
    n_inconclusive: int
    n_not_run: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-compliance-testing.evaluate"
        )


def _compliance_test_payload(rec: "ComplianceTestRecord") -> Dict[str, Any]:
    return {
        "test_id": rec.test_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "compliance_test_kind": rec.compliance_test_kind,
        "outcome": rec.outcome,
        "test_digest": rec.test_digest,
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
        "n_runs": rep.n_runs,
        "n_passed": rep.n_passed,
        "n_failed": rep.n_failed,
        "n_partial": rep.n_partial,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_run": rep.n_not_run,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_compliance_testing_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in EMIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIComplianceTestingError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-compliance-testing",
        "version": AI_COMPLIANCE_TESTING_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIComplianceTesting:
    """AI-compliance-testing declared-execution decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that any system was really compliance-tested.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._runs: Dict[str, ComplianceTestRecord] = {}
        self._system_runs: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._test_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
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
            row = ai_compliance_testing_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-compliance-testing",
                "version": AI_COMPLIANCE_TESTING_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_compliance_testing_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def test(
        self,
        system_id: str,
        seq: int,
        compliance_test_kind: str = "regulatory-compliance-test",
        outcome: str = "passed",
        test_digest: str = "",
    ) -> ComplianceTestRecord:
        """Book one declared compliance test execution run (minted ``cpt-N`` id).

        The first run on an id registers the system. Raw
        compliance-test material, regulatory filings, auditor
        workpapers, corrective-action records, control evidence,
        and raw execution traces never enter records - digest pins
        only.
        Fail-closed: failed mutations consume their seq and book an
        ``ai-compliance-testing.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                compliance_test_kind = _check_compliance_test_kind(
                    compliance_test_kind
                )
                outcome = _check_outcome(outcome)
                test_digest = _check_digest(test_digest, "test_digest")
                self._require_live(system_id)
            except AIComplianceTestingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._test_counter += 1
            test_id = f"cpt-{self._test_counter}"
            provisional = ComplianceTestRecord(
                test_id=test_id,
                system_id=system_id,
                seq=seq,
                compliance_test_kind=compliance_test_kind,
                outcome=outcome,
                test_digest=test_digest,
                digest="",
            )
            digest = _digest_pin(
                _compliance_test_payload(provisional),
                "ai-compliance-testing.test",
            )
            rec = ComplianceTestRecord(
                test_id=test_id,
                system_id=system_id,
                seq=seq,
                compliance_test_kind=compliance_test_kind,
                outcome=outcome,
                test_digest=test_digest,
                digest=digest,
            )
            self._runs[test_id] = rec
            self._system_runs.setdefault(system_id, []).append(test_id)
            self._emit(
                "tested",
                seq,
                test_id=test_id,
                system_id=system_id,
                compliance_test_kind=compliance_test_kind,
                outcome=outcome,
                test_digest=test_digest,
            )
            return rec

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id in self._retired:
                    raise RetiredSystemError(f"system is retired: {system_id!r}")
                if system_id not in self._system_runs:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
            except AIComplianceTestingError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-compliance-testing.retire"
            )
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, test_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one compliance test record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the test really ran. Seq is shape-validated only -
        never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(test_id, bool)
                or not isinstance(test_id, str)
                or test_id not in self._runs
            ):
                raise UnknownComplianceTestError(
                    f"unknown test id: {test_id!r}"
                )
            rec = self._runs[test_id]
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=test_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-compliance-testing.verify"
            )
            return VerificationReport(
                record_id=test_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's compliance-test posture as data.

        Posture by ledger rule: ``untested`` (nothing booked) ->
        ``failing`` (any failed) -> ``inconclusive`` (any inconclusive)
        -> ``partially-tested`` (any partial or not-run) -> ``passed``
        (all passed). ``integrity_ok`` re-derives all in-scope digest
        pins as data. Seq is shape-validated only - never consumed, no
        audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_runs:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            ids = self._system_runs[system_id]
            recs = [self._runs[i] for i in ids]
            n_passed = sum(1 for r in recs if r.outcome == "passed")
            n_failed = sum(1 for r in recs if r.outcome == "failed")
            n_partial = sum(1 for r in recs if r.outcome == "partial")
            n_inconclusive = sum(1 for r in recs if r.outcome == "inconclusive")
            n_not_run = sum(1 for r in recs if r.outcome == "not-run")
            if n_failed:
                posture = "failing"
            elif n_inconclusive:
                posture = "inconclusive"
            elif n_partial or n_not_run:
                posture = "partially-tested"
            elif n_passed and n_passed == len(recs):
                posture = "passed"
            else:
                posture = "untested"
            integrity_ok = all(r.verify() for r in recs)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_runs=len(recs),
                n_passed=n_passed,
                n_failed=n_failed,
                n_partial=n_partial,
                n_inconclusive=n_inconclusive,
                n_not_run=n_not_run,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-compliance-testing.evaluate"
            )
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_runs=len(recs),
                n_passed=n_passed,
                n_failed=n_failed,
                n_partial=n_partial,
                n_inconclusive=n_inconclusive,
                n_not_run=n_not_run,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def test_record(self, test_id: str, seq: int) -> ComplianceTestRecord:
        with self._lock:
            self._check_read_seq(seq)
            if test_id not in self._runs:
                raise UnknownComplianceTestError(
                    f"unknown test id: {test_id!r}"
                )
            return self._runs[test_id]

    def retire_record(self, system_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._check_read_seq(seq)
            if system_id not in self._retired:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return self._retired[system_id]

    def tests_for(self, system_id: str, seq: int) -> Tuple[ComplianceTestRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._runs[i] for i in self._system_runs.get(system_id, []))

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._system_runs))

    def test_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._runs))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_systems": len(self._system_runs),
                "n_runs": len(self._runs),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_COMPLIANCE_TESTING_VERSION,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._audit)


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
    """Self-check: exercise test -> verify -> evaluate."""
    ledger = AIComplianceTesting()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.test(
        "system-1",
        1,
        compliance_test_kind="regulatory-compliance-test",
        outcome="passed",
    )
    assert rec.verify()
    rep = ledger.verify(rec.test_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("system-1", 3)
    assert ev.posture == "passed"
    ret = ledger.retire("system-1", 4)
    assert ret.verify()
    print(
        "ai-compliance-testing OK: test, verify, evaluate, retire, pins, audit"
    )


if __name__ == "__main__":
    main()
