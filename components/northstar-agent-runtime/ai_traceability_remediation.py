"""AI traceability remediation: traceability-issue remediation decision ledger, Simulated.

Research note: Traceability remediation is the field concerned with correcting
declared AI traceability issues once identified - the declared traceability
actions taken (trace-link repairs, lineage-record restorations,
provenance reinstatements, decision-trail reconstructions,
attribution-record fixes, trace-coverage restorations,
lineage-gap closures) and the declared outcomes of those
actions. This module is the *decision ledger* for declared AI traceability
remediation: which traceability-issue ids had which traceability remediations
booked (over a pinned traceability-remediation-kind vocabulary), what
outcomes were declared against them (booked *as data*), and what
remediation posture the ledger derives - defensible bookkeeping, never
proof that an issue is really resolved.

This module owns the remediate -> verify -> evaluate lifecycle:

* **remediate()** - book one declared traceability remediation against a
  declared traceability-issue id (minted ``tcm-N`` ids; pinned
  traceability-remediation-kind vocabulary over the common traceability
  action classes; pinned outcome vocabulary booked *as data*); the first
  remediation registers its issue; traceability reports, monitoring
  streams, escalation records, and raw material never enter records -
  digest pins only.
* **verify()** - **pure read**: re-derive one remediation record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never
  as proof the remediation really ran.
* **evaluate()** - **pure read**: derive one issue's remediation
  posture as data (``unevaluated`` -> ``failed`` -> ``contested`` ->
  ``partially-remediated`` -> ``remediated``) with outcome tallies and a
  digest-pinned integrity flag.
* **retire()** - terminal retirement of an issue id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_remediation.py`` owns the
general remediation-*provision* lifecycle (declared remediation actions
against declared targets over a general action vocabulary);
``ai_transparency_remediation.py`` owns the transparency-*issue*
remediation lifecycle (declared transparency remediations against
transparency-issue ids over a transparency-specific action vocabulary);
``ai_ethics_remediation.py`` owns the ethics-*issue* remediation
lifecycle (declared ethics remediations against ethics-issue ids over an
ethics-specific action vocabulary); ``ai_safety_remediation.py`` owns
the safety-*hazard* remediation lifecycle (declared safety remediations
against safety-hazard ids over a safety-specific action vocabulary);
``ai_fairness_remediation.py`` owns the fairness-*issue* remediation
lifecycle (declared fairness remediations against fairness-issue ids
over a fairness-specific action vocabulary);
``ai_oversight_remediation.py`` owns the oversight-*issue* remediation
lifecycle (declared oversight remediations against oversight-issue ids
over an oversight-specific action vocabulary, minted ``orm-N`` ids);
``ai_compliance_remediation.py`` owns the compliance-*issue* remediation
lifecycle (declared compliance remediations against compliance-issue ids
over a compliance-specific action vocabulary, minted ``crm-N`` ids) -
this module is the traceability-*issue remediation* ledger none of them
own: declared traceability remediations against declared
traceability-issue ids over a traceability-specific action vocabulary,
declared outcomes, digest re-derivation, and the ledger-rule posture that
turns declared outcomes into a remediation claim, always as data, never
as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-traceability-remediation.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no systems, applies
no remediations, and proves nothing about real AI traceability
remediation. A booked ``remediated`` outcome means "the host declared
it", never "the issue is gone"; a booked ``failed`` outcome means "the
host declared it", never "the remediation really failed". Lineage
records, provenance chains, trace links, decision trails, attribution
records, custody logs, and raw remediation material never enter records
or cross the audit boundary - digest pins only.
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
AI_TRACEABILITY_REMEDIATION_VERSION = "ai-traceability-remediation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-traceability-remediation.v1"

#: Pinned traceability-remediation-kind vocabulary (the traceability action classes booked).
TRACEABILITY_REMEDIATION_KINDS = (
    "trace-link-repair",
    "lineage-record-restoration",
    "provenance-reinstatement",
    "decision-trail-reconstruction",
    "attribution-record-fix",
    "trace-coverage-restoration",
    "lineage-gap-closure",
    "no-action",
)

#: Pinned remediation-outcome vocabulary (booked as data, never proof).
REMEDIATION_OUTCOMES = (
    "remediated",
    "partial",
    "failed",
    "inconclusive",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unevaluated",
    "contested",
    "partially-remediated",
    "failed",
    "remediated",
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
    "remediated",
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
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "script",
        "scripts",
        "runbook",
        "runbooks",
        "playbook",
        "playbooks",
        "patch_file",
        "patch_diff",
        "rollback_plan",
        "complaint_log",
        "traceability_assessment",
        "harm_narrative",
        "traceability_report",
        "traceability_restoration_plan",
        "traceability_audit",
        "traceability_structure",
        "governance_record",
        "traceability_gap",
        "traceability_log",
        "traceability_material",
        "lineage_record",
        "lineage_graph",
        "lineage_evidence",
        "lineage_gap",
        "provenance_record",
        "provenance_chain",
        "provenance_evidence",
        "trace_link",
        "trace_record",
        "trace_evidence",
        "trace_log",
        "attribution_record",
        "attribution_evidence",
        "decision_trail",
        "decision_record",
        "decision_log",
        "origin_record",
        "source_record",
        "derivation_log",
        "transformation_log",
        "custody_record",
        "custody_chain",
        "chain_of_custody",
        "artifact_lineage",
        "data_lineage",
        "model_lineage",
        "artifact_registry",
        "reconstruction_plan",
        "monitoring_gap",
        "monitoring_stream",
        "monitoring_config",
        "monitoring_evidence",
        "escalation_record",
        "escalation_path",
        "surveillance_report",
        "surveillance_log",
        "operator_identity",
        "operator_id",
        "duty_roster",
        "watch_schedule",
        "alert_config",
        "alert_payload",
        "intervention_log",
        "override_record",
        "human_review",
        "reviewer_identity",
        "delegation_chain",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AITraceabilityRemediationError(Exception):
    """Base class for all ai-traceability-remediation ledger errors."""


class BadIssueError(AITraceabilityRemediationError):
    pass


class UnknownIssueError(AITraceabilityRemediationError):
    pass


class RetiredIssueError(AITraceabilityRemediationError):
    pass


class BadKindError(AITraceabilityRemediationError):
    pass


class BadOutcomeError(AITraceabilityRemediationError):
    pass


class BadDigestError(AITraceabilityRemediationError):
    pass


class BadReasonError(AITraceabilityRemediationError):
    pass


class UnknownRemediationError(AITraceabilityRemediationError):
    pass


class UnknownRecordError(AITraceabilityRemediationError):
    pass


class SeqOrderError(AITraceabilityRemediationError):
    pass


class AuditKindError(AITraceabilityRemediationError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadIssueError(f"{what} must be a non-empty string")
    return value


def _check_kind(value: Any) -> str:
    if value not in TRACEABILITY_REMEDIATION_KINDS:
        raise BadKindError(
            f"traceability_remediation_kind must be one of {TRACEABILITY_REMEDIATION_KINDS}"
        )
    return value


def _check_outcome(value: Any) -> str:
    if value not in REMEDIATION_OUTCOMES:
        raise BadOutcomeError(f"outcome must be one of {REMEDIATION_OUTCOMES}")
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
    if seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TraceabilityRemediationRecord:
    remediation_id: str
    issue_id: str
    seq: int
    traceability_remediation_kind: str
    outcome: str
    traceability_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _remediate_payload(self), "ai-traceability-remediation.remediate"
        )


@dataclass(frozen=True)
class RetireRecord:
    issue_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-traceability-remediation.retire"
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
            _verify_payload(self), "ai-traceability-remediation.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    issue_id: str
    seq: int
    posture: str
    n_remediations: int
    n_remediated: int
    n_partial: int
    n_failed: int
    n_inconclusive: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-traceability-remediation.evaluate"
        )


def _remediate_payload(rec: "TraceabilityRemediationRecord") -> Dict[str, Any]:
    return {
        "remediation_id": rec.remediation_id,
        "issue_id": rec.issue_id,
        "seq": rec.seq,
        "traceability_remediation_kind": rec.traceability_remediation_kind,
        "outcome": rec.outcome,
        "traceability_digest": rec.traceability_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"issue_id": rec.issue_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "issue_id": rep.issue_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_remediations": rep.n_remediations,
        "n_remediated": rep.n_remediated,
        "n_partial": rep.n_partial,
        "n_failed": rep.n_failed,
        "n_inconclusive": rep.n_inconclusive,
        "integrity_ok": rep.integrity_ok,
    }


def ai_traceability_remediation_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
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
            raise AITraceabilityRemediationError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-traceability-remediation",
        "version": AI_TRACEABILITY_REMEDIATION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AITraceabilityRemediation:
    """AI-traceability-remediation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All traceability remediations
    and outcomes are booked as data - never proof that an issue is really
    resolved.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._remediations: Dict[str, TraceabilityRemediationRecord] = {}
        self._issue_remediations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._remediation_counter = 0
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
            row = ai_traceability_remediation_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-traceability-remediation",
                "version": AI_TRACEABILITY_REMEDIATION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_traceability_remediation_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, issue_id: str) -> None:
        if issue_id in self._retired:
            raise RetiredIssueError(f"issue is retired: {issue_id!r}")

    # -- mutations ---------------------------------------------------------

    def remediate(
        self,
        issue_id: str,
        seq: int,
        traceability_remediation_kind: str = "no-action",
        outcome: str = "inconclusive",
        traceability_digest: str = "",
    ) -> TraceabilityRemediationRecord:
        """Book one declared traceability remediation (minted ``tcm-N`` id).

        The first remediation on an id registers the issue. Lineage
        records, provenance chains, trace links, decision trails,
        and raw material never enter records - digest pins only. Fail-closed: failed mutations
        consume their seq and book an
        ``ai-traceability-remediation.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                issue_id = _check_id(issue_id, "issue_id")
                self._require_seq(seq)
                traceability_remediation_kind = _check_kind(traceability_remediation_kind)
                outcome = _check_outcome(outcome)
                traceability_digest = _check_digest(traceability_digest, "traceability_digest")
                self._require_live(issue_id)
            except AITraceabilityRemediationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._remediation_counter += 1
            remediation_id = f"tcm-{self._remediation_counter}"
            provisional = TraceabilityRemediationRecord(
                remediation_id=remediation_id,
                issue_id=issue_id,
                seq=seq,
                traceability_remediation_kind=traceability_remediation_kind,
                outcome=outcome,
                traceability_digest=traceability_digest,
                digest="",
            )
            digest = _digest_pin(
                _remediate_payload(provisional), "ai-traceability-remediation.remediate"
            )
            rec = TraceabilityRemediationRecord(
                remediation_id=remediation_id,
                issue_id=issue_id,
                seq=seq,
                traceability_remediation_kind=traceability_remediation_kind,
                outcome=outcome,
                traceability_digest=traceability_digest,
                digest=digest,
            )
            self._remediations[remediation_id] = rec
            self._issue_remediations.setdefault(issue_id, []).append(remediation_id)
            self._emit(
                "remediated",
                seq,
                remediation_id=remediation_id,
                issue_id=issue_id,
                traceability_remediation_kind=traceability_remediation_kind,
                outcome=outcome,
            )
            return rec

    def retire(
        self, issue_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminally retire an issue id; ids are never recycled."""
        with self._lock:
            try:
                issue_id = _check_id(issue_id, "issue_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if issue_id not in self._issue_remediations:
                    raise UnknownIssueError(f"unknown issue: {issue_id!r}")
                if issue_id in self._retired:
                    raise RetiredIssueError(
                        f"issue already retired: {issue_id!r}"
                    )
            except AITraceabilityRemediationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                issue_id=issue_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-traceability-remediation.retire"
            )
            rec = RetireRecord(
                issue_id=issue_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[issue_id] = rec
            self._emit("retired", seq, issue_id=issue_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _require_read_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        return seq

    def _integrity_ok(self, issue_id: str) -> bool:
        return all(
            self._remediations[rid].verify()
            for rid in self._issue_remediations.get(issue_id, [])
        )

    def _posture(self, issue_id: str) -> Tuple[str, Dict[str, int]]:
        tallies = {
            "remediated": 0,
            "partial": 0,
            "failed": 0,
            "inconclusive": 0,
        }
        ids = self._issue_remediations.get(issue_id, [])
        for rid in ids:
            tallies[self._remediations[rid].outcome] += 1
        if not ids:
            return "unevaluated", tallies
        if tallies["failed"]:
            return "failed", tallies
        if tallies["inconclusive"]:
            return "contested", tallies
        if tallies["partial"]:
            return "partially-remediated", tallies
        return "remediated", tallies

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one record's digest pin; verdict as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            rec = self._remediations.get(record_id)
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
                _verify_payload(provisional), "ai-traceability-remediation.verify"
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=rec.verify(),
                digest=digest,
            )

    def evaluate(self, issue_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one issue's traceability-remediation posture as data."""
        with self._lock:
            seq = self._require_read_seq(seq)
            issue_id = _check_id(issue_id, "issue_id")
            if issue_id not in self._issue_remediations:
                raise UnknownIssueError(f"unknown issue: {issue_id!r}")
            posture, tallies = self._posture(issue_id)
            provisional = EvaluationReport(
                issue_id=issue_id,
                seq=seq,
                posture=posture,
                n_remediations=len(self._issue_remediations[issue_id]),
                n_remediated=tallies["remediated"],
                n_partial=tallies["partial"],
                n_failed=tallies["failed"],
                n_inconclusive=tallies["inconclusive"],
                integrity_ok=self._integrity_ok(issue_id),
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-traceability-remediation.evaluate"
            )
            return EvaluationReport(
                issue_id=issue_id,
                seq=seq,
                posture=posture,
                n_remediations=len(self._issue_remediations[issue_id]),
                n_remediated=tallies["remediated"],
                n_partial=tallies["partial"],
                n_failed=tallies["failed"],
                n_inconclusive=tallies["inconclusive"],
                integrity_ok=self._integrity_ok(issue_id),
                digest=digest,
            )

    # -- views (pure reads) ------------------------------------------------

    def remediation_record(self, remediation_id: str, seq: int) -> TraceabilityRemediationRecord:
        with self._lock:
            self._require_read_seq(seq)
            rec = self._remediations.get(remediation_id)
            if rec is None:
                raise UnknownRemediationError(
                    f"unknown remediation: {remediation_id!r}"
                )
            return rec

    def remediations_for(
        self, issue_id: str, seq: int
    ) -> Tuple[TraceabilityRemediationRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(
                self._remediations[rid]
                for rid in self._issue_remediations.get(issue_id, [])
            )

    def issue_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._issue_remediations.keys()))

    def remediation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._remediations.keys()))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(sorted(self._retired.keys()))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "seq": self._seq,
                "n_issues": len(self._issue_remediations),
                "n_remediations": len(self._remediations),
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
    """Self-check: exercise remediate -> verify -> evaluate -> retire."""
    ledger = AITraceabilityRemediation()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.remediate(
        "issue-1",
        1,
        traceability_remediation_kind="trace-link-repair",
        outcome="failed",
    )
    assert rec.verify()
    rec2 = ledger.remediate(
        "issue-1", 2, traceability_remediation_kind="lineage-record-restoration", outcome="remediated"
    )
    assert rec2.verify()
    rep = ledger.verify(rec.remediation_id, 3)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("issue-1", 4)
    assert ev.posture == "failed"
    ret = ledger.retire("issue-1", 5)
    assert ret.verify()
    print("ai-traceability-remediation OK: remediate, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
