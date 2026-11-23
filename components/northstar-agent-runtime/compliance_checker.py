"""compliance_checker.py — SOC2 control verification bookkeeping.

SOC2 trust-service-criteria-shaped control checks as a deterministic
single-host state machine. A control is *defined* with required evidence
types; host-reported evidence is then checked against the definition and
a report is produced. The spec API adds the audit engagement layer:
``audit()`` opens an engagement over a pinned scope of controls,
``attest()`` books an auditor's terminal verdict (host-declared data, never
proof of compliance), and ``remediate()`` books remediation intent.
Simulated: the ledger books reported claims, it cannot observe the audited
system and cannot prove a control is truly satisfied (the GIGO boundary
shared with every other bookkeeping module in this repo).
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Tuple

VERSION = "compliance-checker.v1"
SCHEMA = "northstar.compliance-checker.v1"
AUDIT_KINDS = (
    "control-defined",
    "evidence-attached",
    "checked",
    "report-generated",
    "audit-opened",
    "attested",
    "remediated",
    "rejected",
)

# Spec API vocabulary: attestation verdicts and remediation actions.
ATTEST_VERDICTS = ("compliant", "non-compliant", "qualified", "disclaimer")
REMEDIATION_ACTIONS = ("add-control", "fix-evidence", "recheck", "accept-risk")


class ComplianceError(Exception):
    """Base for all compliance_checker errors."""


class UnknownControlError(ComplianceError):
    pass


class DuplicateControlError(ComplianceError):
    pass


class BadEvidenceError(ComplianceError):
    pass


class CheckError(ComplianceError):
    pass


class DuplicateAuditError(ComplianceError):
    pass


class UnknownAuditError(ComplianceError):
    pass


class UncheckedScopeError(ComplianceError):
    pass


class DuplicateAttestationError(ComplianceError):
    pass


class BadVerdictError(ComplianceError):
    pass


class BadActionError(ComplianceError):
    pass


# ---------------------------------------------------------------------------
# Canonical encoding (type-tagged; same caveats as the rest of the batch line)
# ---------------------------------------------------------------------------

_MAX_ABS_INT = 2 ** 53


def _canonical(value: Any) -> str:
    if value is None:
        return "n"
    if isinstance(value, bool):
        return "b:1" if value else "b:0"
    if isinstance(value, int):
        if abs(value) > _MAX_ABS_INT:
            raise BadEvidenceError("int magnitude exceeds 2**53")
        return "i:%d" % value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise BadEvidenceError("NaN/inf refused")
        if value.is_integer() and abs(value) > _MAX_ABS_INT:
            raise BadEvidenceError("integral float magnitude exceeds 2**53")
        return "f:%r" % value
    if isinstance(value, str):
        return "s:%s" % json.dumps(value, ensure_ascii=True)
    if isinstance(value, (bytes, bytearray)):
        raise BadEvidenceError("bytes not canonicalizable")
    if isinstance(value, Mapping):
        items = []
        for k in sorted(value.keys(), key=lambda x: (str(type(x)), str(x))):
            if not isinstance(k, str):
                raise BadEvidenceError("non-str mapping key refused")
            items.append(_canonical(k) + "=>" + _canonical(value[k]))
        return "m:{" + ",".join(items) + "}"
    if isinstance(value, (list, tuple)):
        return "l:[" + ",".join(_canonical(v) for v in value) + "]"
    raise BadEvidenceError("non-canonicalizable evidence type: %r" % type(value).__name__)


def _digest(*parts: str) -> str:
    return "sha256:" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ComplianceError("seq must be a non-negative int")
    return seq


def _check_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ComplianceError("%s must be a non-empty str" % name)
    return value


def _check_mapping(name: str, value: Any) -> Mapping:
    if not isinstance(value, Mapping):
        raise ComplianceError("%s must be a mapping" % name)
    return value


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ControlRecord:
    control_id: str
    framework: str
    description: str
    required_evidence: Tuple[str, ...]
    digest: str
    seq: int
    version: str = VERSION

    def as_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "framework": self.framework,
            "description": self.description,
            "required_evidence": list(self.required_evidence),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    control_id: str
    kind: str
    payload_digest: str
    seq: int
    version: str = VERSION

    def as_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "control_id": self.control_id,
            "kind": self.kind,
            "payload_digest": self.payload_digest,
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class CheckResult:
    control_id: str
    verdict: str  # "pass" | "fail"
    missing: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]
    digest: str
    seq: int
    version: str = VERSION

    def as_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "verdict": self.verdict,
            "missing": list(self.missing),
            "evidence_ids": list(self.evidence_ids),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class ComplianceReport:
    report_id: str
    checked: int
    passed: int
    failed: int
    controls: Tuple[str, ...]
    results_digest: str
    seq: int
    version: str = VERSION

    def as_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "checked": self.checked,
            "passed": self.passed,
            "failed": self.failed,
            "controls": list(self.controls),
            "results_digest": self.results_digest,
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class AuditRecord:
    """An audit engagement with a pinned scope of defined controls."""
    audit_id: str
    scope: Tuple[str, ...]
    scope_digest: str
    digest: str
    seq: int
    version: str = VERSION

    def as_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "scope": list(self.scope),
            "scope_digest": self.scope_digest,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class AttestationRecord:
    """An auditor's attestation over an audit engagement.

    The verdict is host-declared data — ledger truth, never proof that the
    audited system is compliant.
    """
    attestation_id: str
    audit_id: str
    verdict: str  # one of ATTEST_VERDICTS
    auditor: str
    statement_digest: str
    digest: str
    seq: int
    version: str = VERSION

    def as_dict(self) -> dict:
        return {
            "attestation_id": self.attestation_id,
            "audit_id": self.audit_id,
            "verdict": self.verdict,
            "auditor": self.auditor,
            "statement_digest": self.statement_digest,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class RemediationRecord:
    """A booked remediation action against a control.

    Booking is a declaration of intent — never proof the fix landed.
    """
    remediation_id: str
    control_id: str
    action: str  # one of REMEDIATION_ACTIONS
    plan_digest: str
    digest: str
    seq: int
    version: str = VERSION

    def as_dict(self) -> dict:
        return {
            "remediation_id": self.remediation_id,
            "control_id": self.control_id,
            "action": self.action,
            "plan_digest": self.plan_digest,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

class ComplianceChecker:
    """SOC2 control verification bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._controls: dict[str, ControlRecord] = {}
        self._evidence: dict[str, EvidenceRecord] = {}
        self._checks: dict[str, CheckResult] = {}
        self._audits: dict[str, AuditRecord] = {}
        self._attestations: dict[str, AttestationRecord] = {}
        self._remediations: dict[str, RemediationRecord] = {}
        self._evidence_count = 0
        self._report_count = 0
        self._attestation_count = 0
        self._remediation_count = 0
        self._last_seq = -1

    def _monotonic(self, seq: int) -> None:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise ComplianceError("seq must strictly increase (last=%d)" % self._last_seq)
        self._last_seq = seq

    def define_control(
        self,
        control_id: str,
        framework: str,
        description: str,
        required_evidence: Tuple[str, ...],
        seq: int,
    ) -> ControlRecord:
        with self._lock:
            control_id = _check_str("control_id", control_id)
            framework = _check_str("framework", framework)
            description = _check_str("description", description)
            if (not isinstance(required_evidence, (list, tuple)) or not required_evidence
                    or any(not isinstance(k, str) or not k for k in required_evidence)
                    or len(set(required_evidence)) != len(tuple(required_evidence))):
                raise ComplianceError(
                    "required_evidence must be a non-empty tuple of unique non-empty strs")
            required = tuple(required_evidence)
            if control_id in self._controls:
                raise DuplicateControlError("control %r already defined" % control_id)
            self._monotonic(seq)
            digest = _digest("control", control_id, framework, description,
                             ",".join(required), str(seq))
            record = ControlRecord(
                control_id=control_id, framework=framework,
                description=description, required_evidence=required,
                digest=digest, seq=seq)
            self._controls[control_id] = record
            return record

    def attach_evidence(
        self, control_id: str, kind: str, payload: Mapping, seq: int
    ) -> EvidenceRecord:
        with self._lock:
            control_id = _check_str("control_id", control_id)
            kind = _check_str("kind", kind)
            payload = _check_mapping("payload", payload)
            if control_id not in self._controls:
                raise UnknownControlError("unknown control %r" % control_id)
            self._monotonic(seq)
            payload_digest = _digest("payload", _canonical(payload))
            self._evidence_count += 1
            evidence_id = "ev-%d" % self._evidence_count
            record = EvidenceRecord(
                evidence_id=evidence_id, control_id=control_id, kind=kind,
                payload_digest=payload_digest, seq=seq)
            self._evidence[evidence_id] = record
            return record

    def check(self, control_id: str, seq: int) -> CheckResult:
        """Evaluate a control against attached evidence.

        Verdict is "pass" iff evidence of every required kind is attached.
        The verdict books reported evidence — never ground truth.
        """
        with self._lock:
            control_id = _check_str("control_id", control_id)
            if control_id not in self._controls:
                raise UnknownControlError("unknown control %r" % control_id)
            self._monotonic(seq)
            required = self._controls[control_id].required_evidence
            attached = sorted(
                {rec.kind for rec in self._evidence.values()
                 if rec.control_id == control_id})
            missing = tuple(k for k in required if k not in attached)
            evidence_ids = tuple(
                sorted(rec.evidence_id for rec in self._evidence.values()
                       if rec.control_id == control_id))
            verdict = "pass" if not missing else "fail"
            digest = _digest("check", control_id, verdict,
                             ",".join(missing), ",".join(evidence_ids), str(seq))
            result = CheckResult(
                control_id=control_id, verdict=verdict, missing=missing,
                evidence_ids=evidence_ids, digest=digest, seq=seq)
            self._checks[control_id] = result
            return result

    def evidence(self, control_id: str | None = None) -> Tuple[EvidenceRecord, ...]:
        with self._lock:
            if control_id is None:
                return tuple(sorted(self._evidence.values(),
                                    key=lambda r: r.evidence_id))
            control_id = _check_str("control_id", control_id)
            if control_id not in self._controls:
                raise UnknownControlError("unknown control %r" % control_id)
            return tuple(sorted(
                (r for r in self._evidence.values() if r.control_id == control_id),
                key=lambda r: r.evidence_id))

    def report(self, seq: int) -> ComplianceReport:
        with self._lock:
            self._monotonic(seq)
            controls = tuple(sorted(self._controls))
            checked = len(self._checks)
            passed = sum(1 for r in self._checks.values() if r.verdict == "pass")
            failed = checked - passed
            results_digest = _digest(
                "report",
                ",".join(sorted(r.control_id + ":" + r.verdict
                                for r in self._checks.values())),
                str(seq))
            self._report_count += 1
            return ComplianceReport(
                report_id="report-%d" % self._report_count,
                checked=checked, passed=passed, failed=failed,
                controls=controls, results_digest=results_digest, seq=seq)

    def controls(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._controls))

    def control(self, control_id: str) -> ControlRecord:
        with self._lock:
            control_id = _check_str("control_id", control_id)
            if control_id not in self._controls:
                raise UnknownControlError("unknown control %r" % control_id)
            return self._controls[control_id]

    # ------------------------------------------------------------------
    # Spec API: audit / attest / remediate (additive)
    # ------------------------------------------------------------------

    def audit(
        self, audit_id: str, control_ids: Tuple[str, ...], seq: int
    ) -> AuditRecord:
        """Open an audit engagement with a pinned scope of defined controls.

        The scope is sorted for a deterministic pin; every control id must be
        defined. Audit ids are never recycled.
        """
        with self._lock:
            audit_id = _check_str("audit_id", audit_id)
            if (not isinstance(control_ids, (list, tuple)) or not control_ids
                    or any(not isinstance(c, str) or not c for c in control_ids)
                    or len(set(control_ids)) != len(tuple(control_ids))):
                raise ComplianceError(
                    "control_ids must be a non-empty tuple of unique non-empty strs")
            for control_id in control_ids:
                if control_id not in self._controls:
                    raise UnknownControlError("unknown control %r" % control_id)
            if audit_id in self._audits:
                raise DuplicateAuditError("audit %r already opened" % audit_id)
            self._monotonic(seq)
            scope = tuple(sorted(control_ids))
            scope_digest = _digest("audit-scope", ",".join(scope))
            digest = _digest("audit", audit_id, ",".join(scope), str(seq))
            record = AuditRecord(
                audit_id=audit_id, scope=scope, scope_digest=scope_digest,
                digest=digest, seq=seq)
            self._audits[audit_id] = record
            return record

    def attest(
        self, audit_id: str, verdict: str, seq: int, auditor: str = ""
    ) -> AttestationRecord:
        """Book an auditor's attestation over an audit engagement.

        The verdict is host-declared data, never proof of compliance.
        Attestation is terminal per audit and fail-closed when any in-scope
        control has not been checked.
        """
        with self._lock:
            audit_id = _check_str("audit_id", audit_id)
            if not isinstance(verdict, str) or verdict not in ATTEST_VERDICTS:
                raise BadVerdictError(
                    "verdict must be one of %s" % (", ".join(ATTEST_VERDICTS),))
            if not isinstance(auditor, str):
                raise ComplianceError("auditor must be a str")
            if audit_id not in self._audits:
                raise UnknownAuditError("unknown audit %r" % audit_id)
            if audit_id in self._attestations:
                raise DuplicateAttestationError(
                    "audit %r already attested" % audit_id)
            scope = self._audits[audit_id].scope
            unchecked = tuple(c for c in scope if c not in self._checks)
            if unchecked:
                raise UncheckedScopeError(
                    "audit %r scope not fully checked: %s"
                    % (audit_id, ",".join(unchecked)))
            self._monotonic(seq)
            self._attestation_count += 1
            attestation_id = "attest-%d" % self._attestation_count
            statement_digest = _digest("attestation-statement", audit_id,
                                       verdict, auditor)
            digest = _digest("attest", audit_id, verdict, auditor, str(seq))
            record = AttestationRecord(
                attestation_id=attestation_id, audit_id=audit_id,
                verdict=verdict, auditor=auditor,
                statement_digest=statement_digest, digest=digest, seq=seq)
            self._attestations[audit_id] = record
            return record

    def remediate(
        self, control_id: str, action: str, seq: int, plan_digest: str = ""
    ) -> RemediationRecord:
        """Book a remediation action against a control.

        Booking is a declaration of intent — never proof the fix landed.
        The plan travels as a digest pin only; raw plans never enter records.
        """
        with self._lock:
            control_id = _check_str("control_id", control_id)
            if control_id not in self._controls:
                raise UnknownControlError("unknown control %r" % control_id)
            if not isinstance(action, str) or action not in REMEDIATION_ACTIONS:
                raise BadActionError(
                    "action must be one of %s"
                    % (", ".join(REMEDIATION_ACTIONS),))
            if plan_digest and (not isinstance(plan_digest, str)
                                or not plan_digest.startswith("sha256:")):
                raise ComplianceError("plan_digest must be a sha256: pin")
            self._monotonic(seq)
            self._remediation_count += 1
            remediation_id = "rem-%d" % self._remediation_count
            digest = _digest("remediate", control_id, action, str(seq))
            record = RemediationRecord(
                remediation_id=remediation_id, control_id=control_id,
                action=action, plan_digest=plan_digest, digest=digest,
                seq=seq)
            self._remediations[remediation_id] = record
            return record

    def audit_record(self, audit_id: str) -> AuditRecord:
        with self._lock:
            audit_id = _check_str("audit_id", audit_id)
            if audit_id not in self._audits:
                raise UnknownAuditError("unknown audit %r" % audit_id)
            return self._audits[audit_id]

    def attestation_record(self, audit_id: str) -> AttestationRecord:
        with self._lock:
            audit_id = _check_str("audit_id", audit_id)
            if audit_id not in self._attestations:
                raise UnknownAuditError("no attestation for audit %r" % audit_id)
            return self._attestations[audit_id]

    def remediation_record(self, remediation_id: str) -> RemediationRecord:
        with self._lock:
            remediation_id = _check_str("remediation_id", remediation_id)
            if remediation_id not in self._remediations:
                raise ComplianceError("unknown remediation %r" % remediation_id)
            return self._remediations[remediation_id]

    def audit_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._audits))


def compliance_checker_audit_event(
    kind: str, seq: int, control_id: str = "", detail: str = ""
) -> dict:
    if kind not in AUDIT_KINDS:
        raise ComplianceError("unknown audit kind %r" % kind)
    _check_seq(seq)
    return {
        "schema": SCHEMA,
        "kind": kind,
        "control_id": control_id,
        "detail": detail,
        "seq": seq,
    }


def main() -> None:
    cc = ComplianceChecker()
    cc.define_control("CC6.1", "SOC2", "logical access security",
                      ("access-review", "policy-doc"), 0)
    ev = cc.attach_evidence("CC6.1", "access-review",
                            {"reviewer": "sec-team", "quarter": "Q3"}, 1)
    assert ev.evidence_id == "ev-1"
    result = cc.check("CC6.1", 2)
    assert result.verdict == "fail" and result.missing == ("policy-doc",)
    cc.attach_evidence("CC6.1", "policy-doc", {"version": "3"}, 3)
    result = cc.check("CC6.1", 4)
    assert result.verdict == "pass" and result.missing == ()
    rep = cc.report(5)
    assert rep.checked == 1 and rep.passed == 1 and rep.failed == 0
    try:
        cc.define_control("CC6.1", "SOC2", "dup", ("x",), 6)
    except DuplicateControlError:
        pass
    else:
        raise AssertionError("duplicate control accepted")
    try:
        cc.attach_evidence("NOPE", "x", {}, 7)
    except UnknownControlError:
        pass
    else:
        raise AssertionError("unknown control accepted")
    # Spec API: audit / attest / remediate
    aud = cc.audit("audit-2026", ("CC6.1",), 8)
    assert aud.scope == ("CC6.1",) and aud.audit_id == "audit-2026"
    att = cc.attest("audit-2026", "compliant", 9, auditor="ext-auditor")
    assert att.attestation_id == "attest-1" and att.verdict == "compliant"
    rem = cc.remediate("CC6.1", "recheck", 10)
    assert rem.remediation_id == "rem-1" and rem.action == "recheck"
    try:
        cc.attest("audit-2026", "compliant", 11)
    except DuplicateAttestationError:
        pass
    else:
        raise AssertionError("double attestation accepted")
    try:
        cc.remediate("NOPE", "recheck", 12)
    except UnknownControlError:
        pass
    else:
        raise AssertionError("unknown remediation control accepted")
    print("compliance-checker OK: define, attach, check, report, refusals")
    print("compliance-checker spec OK: audit, attest, remediate")


if __name__ == "__main__":
    main()
