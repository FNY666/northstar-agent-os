"""AI containment: containment declare/verify decision ledger, Simulated.

Research note: containment is where declared control meets declared
agent deployments - when a host says an agent deployment is boxed in
(network-isolated, tool-revoked, sandboxed, frozen, terminated,
capability-restricted, rolled back, throttled), this module is the
*decision ledger* for those declarations: which target ids had which
containment measures booked (over a pinned measure vocabulary), what
declared releases were booked against them, and what containment
posture the ledger derives - defensible bookkeeping, never proof that
the target was really contained.

This module owns the contain -> verify -> evaluate lifecycle:

* **contain()** - book one declared containment measure (minted
  ``cnt-N`` ids; pinned measure vocabulary; host-reported severity int
  in [0,100] booked *as data*); the first measure registers its
  target; raw sandbox configs, network traces, tool logs, and model
  internals never enter records - digest pins only.
* **release()** - terminal release of a target id from containment;
  ids are never recycled; fail-closed on unknown or released targets.
* **verify()** - **pure read**: re-derive one containment record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never
  as proof the target was really contained.
* **evaluate()** - **pure read**: derive one target's containment
  posture as data (``released`` -> ``breached`` -> ``contained`` ->
  ``uncontained`` for never-seen targets) with measure tallies and a
  digest-pinned integrity flag.

Distinct-layer rationale vs siblings: ``ai_safety.py`` owns the
assessment -> mitigation lifecycle (declared hazards and their
mitigations); ``ai_incident.py`` owns the report -> investigate
lifecycle (declared incidents and their investigations); ``ai_monitoring.py``
and siblings own declared detection/alert postures - this module is the
*containment* lifecycle none of them own: declared containment
measures, declared releases, digest re-derivation, and the ledger-rule
posture that turns declared measures into a containment claim, always
as data, never as measured containment truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-containment.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module contains nothing, proves nothing about
real-world containment, and breaches no real sandbox. A booked
``contained`` posture means "the host declared it", never "the target
is contained"; a booked ``breached`` posture means "a digest pin failed
to re-derive", never "a real breach occurred". Sandbox configs,
network traces, tool logs, model internals, raw transcripts, and
identity material never enter records or cross the audit boundary -
digest pins only.
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
AI_CONTAINMENT_VERSION = "ai-containment.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-containment.v1"

#: Pinned containment-measure vocabulary (the declared measures).
MEASURES = (
    "network-isolation",
    "tool-revocation",
    "sandbox-quarantine",
    "model-freeze",
    "session-terminate",
    "capability-restrict",
    "checkpoint-rollback",
    "rate-throttle",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data), with precedence order
#: released > breached > contained > uncontained.
POSTURES = (
    "uncontained",
    "contained",
    "breached",
    "released",
)

#: Pinned release-reason vocabulary.
RELEASE_REASONS = (
    "manual",
    "superseded",
    "all-clear",
    "false-start",
)

#: Severity at or above which a containment measure is critical.
CRITICAL_SEVERITY = 75

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "contained",
    "released",
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
        "evidence",
        "findings",
        "report",
        "reports",
        "workpapers",
        "interview",
        "interviews",
        "questionnaire",
        "checklist",
        "incident",
        "incident_description",
        "incident_details",
        "incident_text",
        "incident_report_text",
        "impact",
        "impact_assessment",
        "impact_narrative",
        "harm",
        "harm_description",
        "harm_narrative",
        "injury",
        "damage",
        "damages",
        "victim",
        "victim_id",
        "victim_identity",
        "reporter",
        "reporter_id",
        "reporter_identity",
        "forensics",
        "forensic_data",
        "timeline",
        "root_cause",
        "causal_chain",
        "attack_chain",
        "exploit",
        "payload",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "personal_data",
        "personal_information",
        "identity",
        "identity_document",
        "document",
        "documents",
        "medical_record",
        "financial_record",
        "settlement",
        "settlement_terms",
        "agreement",
        "legal_filing",
        "court_order",
        "claim",
        "claim_details",
        "claim_text",
        "compensation_amount",
        "payout",
        "payment",
        "payment_details",
        "bank_details",
        "sandbox_config",
        "network_config",
        "firewall_rules",
        "tool_logs",
        "session_dump",
        "capability_matrix",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIContainmentError(Exception):
    """Base class for all ai-containment ledger errors."""


class BadTargetError(AIContainmentError):
    pass


class UnknownTargetError(AIContainmentError):
    pass


class ReleasedTargetError(AIContainmentError):
    pass


class BadMeasureError(AIContainmentError):
    pass


class BadSeverityError(AIContainmentError):
    pass


class BadDigestError(AIContainmentError):
    pass


class BadReasonError(AIContainmentError):
    pass


class UnknownRecordError(AIContainmentError):
    pass


class SeqOrderError(AIContainmentError):
    pass


class AuditKindError(AIContainmentError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadTargetError(f"{what} must be a non-empty string")
    return value


def _check_measure(value: Any) -> str:
    if value not in MEASURES:
        raise BadMeasureError(f"measure must be one of {MEASURES}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int in [0, 100]")
    if not 0 <= value <= 100:
        raise BadSeverityError("severity must be an int in [0, 100]")
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
    if value not in RELEASE_REASONS:
        raise BadReasonError(f"reason must be one of {RELEASE_REASONS}")
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
class ContainmentRecord:
    containment_id: str
    target_id: str
    seq: int
    measure: str
    severity: int
    measure_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _contain_payload(self), "ai-containment.contain"
        )


@dataclass(frozen=True)
class ReleaseRecord:
    target_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _release_payload(self), "ai-containment.release"
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
            _verify_payload(self), "ai-containment.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    target_id: str
    seq: int
    posture: str
    n_measures: int
    n_critical: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-containment.evaluate"
        )


def _contain_payload(rec: "ContainmentRecord") -> Dict[str, Any]:
    return {
        "containment_id": rec.containment_id,
        "target_id": rec.target_id,
        "seq": rec.seq,
        "measure": rec.measure,
        "severity": rec.severity,
        "measure_digest": rec.measure_digest,
    }


def _release_payload(rec: "ReleaseRecord") -> Dict[str, Any]:
    return {"target_id": rec.target_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "target_id": rep.target_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_measures": rep.n_measures,
        "n_critical": rep.n_critical,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_containment_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIContainmentError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-containment",
        "version": AI_CONTAINMENT_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIContainment:
    """AI-containment declare/verify decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All measures, severities,
    and postures are booked as data - never proof that a real target was
    really contained.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._records: Dict[str, ContainmentRecord] = {}
        self._target_records: Dict[str, List[str]] = {}
        self._released: Dict[str, ReleaseRecord] = {}
        self._counter = 0
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
            row = ai_containment_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-containment",
                "version": AI_CONTAINMENT_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_containment_audit_event(audit_kind, seq, **details))

    def _require_live(self, target_id: str) -> None:
        if target_id in self._released:
            raise ReleasedTargetError(f"target is released: {target_id!r}")

    # -- mutations ---------------------------------------------------------

    def contain(
        self,
        target_id: str,
        seq: int,
        measure: str = "network-isolation",
        severity: int = 0,
        measure_digest: str = "",
    ) -> ContainmentRecord:
        """Book one declared containment measure (minted ``cnt-N`` id).

        The first measure on an id registers the target. Raw sandbox
        configs, network traces, tool logs, and model internals never
        enter records - digest pins only. Fail-closed: failed mutations
        consume their seq and book an ``ai-containment.rejected`` row;
        rewinds raise bare.
        """
        with self._lock:
            try:
                target_id = _check_id(target_id, "target_id")
                self._require_seq(seq)
                measure = _check_measure(measure)
                severity = _check_severity(severity)
                measure_digest = _check_digest(measure_digest, "measure_digest")
                self._require_live(target_id)
            except AIContainmentError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._counter += 1
            containment_id = f"cnt-{self._counter}"
            provisional = ContainmentRecord(
                containment_id=containment_id,
                target_id=target_id,
                seq=seq,
                measure=measure,
                severity=severity,
                measure_digest=measure_digest,
                digest="",
            )
            digest = _digest_pin(
                _contain_payload(provisional), "ai-containment.contain"
            )
            rec = ContainmentRecord(
                containment_id=containment_id,
                target_id=target_id,
                seq=seq,
                measure=measure,
                severity=severity,
                measure_digest=measure_digest,
                digest=digest,
            )
            self._records[containment_id] = rec
            self._target_records.setdefault(target_id, []).append(containment_id)
            self._emit(
                "contained",
                seq,
                containment_id=containment_id,
                target_id=target_id,
                measure=measure,
                severity=severity,
                measure_digest=measure_digest,
            )
            return rec

    def release(
        self, target_id: str, seq: int, reason: str = "manual"
    ) -> ReleaseRecord:
        """Terminal release of a target id from containment; ids are never recycled."""
        with self._lock:
            try:
                target_id = _check_id(target_id, "target_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if target_id in self._released:
                    raise ReleasedTargetError(f"target is released: {target_id!r}")
                if target_id not in self._target_records:
                    raise UnknownTargetError(f"unknown target: {target_id!r}")
            except AIContainmentError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = ReleaseRecord(
                target_id=target_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _release_payload(provisional), "ai-containment.release"
            )
            rec = ReleaseRecord(
                target_id=target_id, seq=seq, reason=reason, digest=digest
            )
            self._released[target_id] = rec
            self._emit("released", seq, target_id=target_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one containment record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the target was really contained. Seq is shape-validated
        only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            rec = self._records.get(record_id)
            if (
                rec is None
                or isinstance(record_id, bool)
                or not isinstance(record_id, str)
            ):
                raise UnknownRecordError(f"unknown record id: {record_id!r}")
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-containment.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, target_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one target's containment posture as data.

        Posture by ledger rule: ``released`` (target released) ->
        ``breached`` (any in-scope record digest fails to re-derive) ->
        ``contained`` (at least one booked measure) -> ``uncontained``
        (target never seen - booked as data, never as proof the target
        is free). ``integrity_ok`` re-derives all in-scope digest pins
        as data. Seq is shape-validated only - never consumed, no audit
        row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            target_id = _check_id(target_id, "target_id")
            record_ids = self._target_records.get(target_id, [])
            records = [self._records[i] for i in record_ids]
            if target_id in self._released:
                posture = "released"
            elif not records:
                posture = "uncontained"
            elif not all(r.verify() for r in records):
                posture = "breached"
            else:
                posture = "contained"
            integrity_ok = all(r.verify() for r in records)
            n_critical = sum(1 for r in records if r.severity >= CRITICAL_SEVERITY)
            provisional = EvaluationReport(
                target_id=target_id,
                seq=seq,
                posture=posture,
                n_measures=len(records),
                n_critical=n_critical,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-containment.evaluate"
            )
            return EvaluationReport(
                target_id=target_id,
                seq=seq,
                posture=posture,
                n_measures=len(records),
                n_critical=n_critical,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def containment_record(self, containment_id: str, seq: int) -> ContainmentRecord:
        with self._lock:
            self._check_read_seq(seq)
            if containment_id not in self._records:
                raise UnknownRecordError(
                    f"unknown containment id: {containment_id!r}"
                )
            return self._records[containment_id]

    def release_record(self, target_id: str, seq: int) -> ReleaseRecord:
        with self._lock:
            self._check_read_seq(seq)
            if target_id not in self._released:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            return self._released[target_id]

    def records_for(self, target_id: str, seq: int) -> Tuple[ContainmentRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._records[i] for i in self._target_records.get(target_id, [])
            )

    def target_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._target_records))

    def containment_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._records))

    def released_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._released))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_targets": len(self._target_records),
                "n_records": len(self._records),
                "n_released": len(self._released),
                "seq": self._seq,
                "version": AI_CONTAINMENT_VERSION,
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
    """Self-check: exercise contain -> verify -> evaluate -> release."""
    ledger = AIContainment()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.contain("target-1", 1, measure="sandbox-quarantine", severity=80)
    assert rec.verify()
    rep = ledger.verify(rec.containment_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("target-1", 3)
    assert ev.posture == "contained" and ev.n_critical == 1
    ev2 = ledger.evaluate("never-seen", 4)
    assert ev2.posture == "uncontained" and ev2.n_measures == 0
    rel = ledger.release("target-1", 5, reason="all-clear")
    assert rel.verify()
    ev3 = ledger.evaluate("target-1", 6)
    assert ev3.posture == "released"
    print("ai-containment OK: contain, verify, evaluate, release, pins, audit")


if __name__ == "__main__":
    main()
