"""Compliance governance ledger: frameworks, control checks, remediation, attestation.

A ``Compliance`` books a declared compliance workflow -- control checks
against a registered framework, declared remediation of failing checks,
and derived compliance attestation reports -- as a deterministic
single-host state machine. This module owns the *compliance decision
ledger* layer, deliberately distinct from siblings:

* ``compliance_checker.py`` -- control-assessment mechanics.
* ``compliance_reports.py`` -- report rendering.
* ``step_compliance.py`` -- per-step compliance gates.
* This module -- which framework registered which controls, which checks
  ran, what each declared, which failures were remediated, and what the
  derived compliance posture is.

Workflow:

1. ``register_framework(framework_id, framework_kind, seq, ...)``
   declares one compliance framework under a pinned kind vocabulary;
   raw policy text never enters the ledger -- digest pins only.
2. ``check(framework_id, control_id, verdict, seq, ...)`` books one
   host-declared control check (minted ``chk-N``); verdicts are *data*
   (``pass`` / ``fail`` / ``partial`` / ``not-applicable``), never proof
   of actual compliance.
3. ``remediate(check_id, action, seq, ...)`` books one declared
   remediation against a failing check (minted ``rmd-N``); one
   remediation per check; books the *declaration*, never the actual fix.
4. ``attest(framework_id, seq)`` is a pure read deriving the
   compliance posture as data (``compliant`` / ``non-compliant`` /
   ``not-assessed``) from the booked checks and remediations.

House style: frozen dataclasses, caller-supplied int seqs strictly
increasing (claim-then-burn: failed mutations consume their seq and
book ``compliance.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only (plus the
sanctioned ``canonical_json`` try/except fallback), ``sha256:`` digest
pins with ``verify()``, ``audit.ndjson/1`` events with raw policy and
evidence content banned from the audit boundary, version/schema pins,
``main()`` self-check.

Honest scope: checks are host-declared GIGO -- a booked ``pass`` means
the host declared this outcome, never that a control is actually
satisfied. Attestation books a declared posture derived from ledger
truth, never proof of audit readiness. This module runs no scanner,
contacts no auditor, and proves nothing about regulatory standing.

Version pin: compliance.v1
Schema pin: northstar.compliance.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Dict, List, Tuple

try:  # pragma: no cover - repo may ship canonical_json as a module
    from canonical_json import jcs_dumps as _jcs_dumps
except Exception:  # pragma: no cover - stdlib fallback
    import json as _json

    def _jcs_dumps(obj) -> str:
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True)

#: Module version pin.
COMPLIANCE_VERSION = "compliance.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.compliance.v1"

#: Schema pin for audit rows.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Framework-kind vocabulary.
KIND_SOC2 = "soc2"
KIND_HIPAA = "hipaa"
KIND_GDPR = "gdpr"
KIND_ISO27001 = "iso27001"
KIND_PCI_DSS = "pci-dss"
KIND_NIST_800_53 = "nist-800-53"
KIND_CUSTOM = "custom"
_FRAMEWORK_KINDS = frozenset(
    {
        KIND_SOC2,
        KIND_HIPAA,
        KIND_GDPR,
        KIND_ISO27001,
        KIND_PCI_DSS,
        KIND_NIST_800_53,
        KIND_CUSTOM,
    }
)

#: Check-verdict vocabulary (booked as data, never proof).
VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_PARTIAL = "partial"
VERDICT_NA = "not-applicable"
_VERDICTS = frozenset(
    {
        VERDICT_PASS,
        VERDICT_FAIL,
        VERDICT_PARTIAL,
        VERDICT_NA,
    }
)

#: Remediation-action vocabulary.
ACTION_PATCH = "patch"
ACTION_RECONFIGURE = "reconfigure"
ACTION_DOCUMENT = "document"
ACTION_ACCEPT_RISK = "accept-risk"
ACTION_MITIGATE = "mitigate"
ACTION_ESCALATE = "escalate"
_ACTIONS = frozenset(
    {
        ACTION_PATCH,
        ACTION_RECONFIGURE,
        ACTION_DOCUMENT,
        ACTION_ACCEPT_RISK,
        ACTION_MITIGATE,
        ACTION_ESCALATE,
    }
)

#: Audit event kinds.
KIND_REGISTERED = "compliance.registered"
KIND_CHECKED = "compliance.checked"
KIND_REMEDIATED = "compliance.remediated"
KIND_REJECTED = "compliance.rejected"

_KINDS = frozenset(
    {
        KIND_REGISTERED,
        KIND_CHECKED,
        KIND_REMEDIATED,
        KIND_REJECTED,
    }
)

#: Detail keys that must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset(
    {
        "policy",
        "raw",
        "content",
        "payload",
        "evidence",
        "notes",
        "note",
        "transcript",
        "data",
        "value",
        "values",
        "text",
        "description",
        "remediation",
        "finding",
        "details",
    }
)


class ComplianceError(Exception):
    """Base fail-closed error for the compliance ledger."""


class BadIdError(ComplianceError):
    """Malformed framework, control, or record id."""


class DuplicateFrameworkError(ComplianceError):
    """Framework id already registered in this ledger."""


class UnknownFrameworkError(ComplianceError):
    """Framework id not known to this ledger."""


class BadFrameworkKindError(ComplianceError):
    """Framework kind outside the pinned vocabulary."""


class BadDigestError(ComplianceError):
    """Digest is not a sha256 pin."""


class BadVerdictError(ComplianceError):
    """Check verdict outside the pinned vocabulary."""


class BadActionError(ComplianceError):
    """Remediation action outside the pinned vocabulary."""


class UnknownCheckError(ComplianceError):
    """Check id not known to this ledger."""


class CheckNotFailingError(ComplianceError):
    """Remediation booked against a non-failing check."""


class AlreadyRemediatedError(ComplianceError):
    """Check already has a booked remediation."""


class SeqOrderError(ComplianceError):
    """Caller seq did not strictly increase."""


class AuditKindError(ComplianceError):
    """Unknown audit kind or banned detail key."""


def _check_seq(seq: object) -> int:
    """Validate a caller-supplied seq (int, non-bool, non-negative)."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _check_id(name: str, value: object) -> str:
    """Validate a non-empty string identifier."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{name} must be a str, got {type(value).__name__}")
    if not value or len(value) > 256:
        raise BadIdError(f"{name} must be 1..256 chars")
    if value != value.strip():
        raise BadIdError(f"{name} must not have surrounding whitespace")
    return value


def _check_digest(name: str, value: object) -> str:
    """Validate a sha256 digest pin (sha256:<64hex>)."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(
            f"{name} must be a str, got {type(value).__name__}")
    if not value.startswith("sha256:") or len(value) != 71:
        raise BadDigestError(f"{name} must be 'sha256:' + 64 hex chars")
    try:
        int(value[7:], 16)
    except ValueError:
        raise BadDigestError(f"{name} hex part is not hex") from None
    return value


def _check_optional_digest(name: str, value: object) -> str:
    """Validate an empty string or a sha256 digest pin."""
    if value == "":
        return ""
    return _check_digest(name, value)


def _pin(*parts: object) -> str:
    """Deterministic sha256 pin over canonical JSON of parts."""
    canonical = _jcs_dumps([str(p) for p in parts])
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compliance_audit_event(audit_kind: str, detail: Dict[str, object],
                            seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the compliance ledger."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": COMPLIANCE_VERSION,
        "kind": audit_kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class FrameworkRecord:
    """Frozen record of one registered compliance framework."""

    framework_id: str
    framework_kind: str
    policy_digest: str
    seq: int
    digest: str

    def verify(self, framework_id: str, framework_kind: str,
               policy_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        expect = _pin("framework", framework_id, framework_kind,
                      policy_digest)
        return self.digest == expect


@dataclass(frozen=True)
class CheckRecord:
    """Frozen record of one declared control check (minted chk-N)."""

    check_id: str
    framework_id: str
    control_id: str
    verdict: str
    evidence_digest: str
    seq: int
    digest: str

    def verify(self, framework_id: str, control_id: str, verdict: str,
               evidence_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        expect = _pin("check", framework_id, control_id, verdict,
                      evidence_digest)
        return self.digest == expect


@dataclass(frozen=True)
class RemediationRecord:
    """Frozen record of one declared remediation (minted rmd-N)."""

    remediation_id: str
    check_id: str
    action: str
    detail_digest: str
    seq: int
    digest: str

    def verify(self, check_id: str, action: str,
               detail_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        expect = _pin("remediation", check_id, action, detail_digest)
        return self.digest == expect


@dataclass(frozen=True)
class AttestationReport:
    """Frozen derived compliance posture for one framework.

    ``posture`` is data: ``compliant`` (at least one assessed check and
    no unremediated failures), ``non-compliant`` (at least one
    unremediated failure), or ``not-assessed`` (no assessed checks).
    """

    framework_id: str
    posture: str
    n_checks: int
    n_passed: int
    n_failed: int
    n_remediated: int
    seq: int
    digest: str

    def verify(self, framework_id: str, posture: str, n_checks: int,
               n_passed: int, n_failed: int, n_remediated: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        expect = _pin("attestation", framework_id, posture, n_checks,
                      n_passed, n_failed, n_remediated)
        return self.digest == expect


class Compliance:
    """Compliance decision ledger: register, check, remediate, attest.

    Deterministic single-host state machine. Caller-supplied seqs must
    strictly increase; failed mutations consume their seq and book a
    ``compliance.rejected`` audit row; rewinds raise bare. Pure-read
    views validate seq shape, never consume, and write no audit rows.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._frameworks: Dict[str, FrameworkRecord] = {}
        self._checks: Dict[str, CheckRecord] = {}
        self._remediations: Dict[str, RemediationRecord] = {}
        self._checks_by_framework: Dict[str, List[str]] = {}
        self._remediation_by_check: Dict[str, str] = {}
        self._audit: List[Dict[str, object]] = []
        self._next_check = 1
        self._next_remediation = 1

    # -- internal ----------------------------------------------------

    def _claim(self, seq: object) -> int:
        """Shape-validate seq and advance the clock (fail-closed)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} does not strictly increase after "
                f"{self._last_seq}")
        self._last_seq = seq
        return seq

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit row (raw-content keys banned by the builder)."""
        self._audit.append(compliance_audit_event(audit_kind, detail, seq))

    def _reject(self, seq: int, reason: str) -> None:
        """Book a rejected-mutation row (claim-then-burn)."""
        self._emit(KIND_REJECTED, {"reason": reason}, seq)

    # -- mutations ---------------------------------------------------

    def register_framework(self, framework_id: str, framework_kind: str,
                            seq: object,
                            policy_digest: str = "") -> FrameworkRecord:
        """Declare one compliance framework; raw policy stays out."""
        with self._lock:
            seq = self._claim(seq)
            try:
                framework_id = _check_id("framework_id", framework_id)
                if framework_kind not in _FRAMEWORK_KINDS:
                    raise BadFrameworkKindError(
                        f"framework_kind {framework_kind!r} outside "
                        "pinned vocabulary")
                policy_digest = _check_optional_digest("policy_digest",
                                                       policy_digest)
                if framework_id in self._frameworks:
                    raise DuplicateFrameworkError(
                        f"framework already registered: {framework_id!r}")
                rec = FrameworkRecord(
                    framework_id=framework_id,
                    framework_kind=framework_kind,
                    policy_digest=policy_digest,
                    seq=seq,
                    digest=_pin("framework", framework_id, framework_kind,
                                policy_digest),
                )
            except ComplianceError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            self._frameworks[framework_id] = rec
            self._checks_by_framework[framework_id] = []
            self._emit(KIND_REGISTERED,
                       {"framework_id": framework_id,
                        "framework_kind": framework_kind},
                       seq)
            return rec

    def check(self, framework_id: str, control_id: str, verdict: str,
              seq: object, evidence_digest: str = "") -> CheckRecord:
        """Book one declared control check (minted chk-N id)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                framework_id = _check_id("framework_id", framework_id)
                control_id = _check_id("control_id", control_id)
                if framework_id not in self._frameworks:
                    raise UnknownFrameworkError(
                        f"unknown framework: {framework_id!r}")
                if verdict not in _VERDICTS:
                    raise BadVerdictError(
                        f"verdict {verdict!r} outside pinned vocabulary")
                evidence_digest = _check_optional_digest("evidence_digest",
                                                         evidence_digest)
                check_id = f"chk-{self._next_check}"
                self._next_check += 1
                rec = CheckRecord(
                    check_id=check_id,
                    framework_id=framework_id,
                    control_id=control_id,
                    verdict=verdict,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=_pin("check", framework_id, control_id, verdict,
                                evidence_digest),
                )
            except ComplianceError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            self._checks[check_id] = rec
            self._checks_by_framework[framework_id].append(check_id)
            self._emit(KIND_CHECKED,
                       {"check_id": check_id, "framework_id": framework_id,
                        "control_id": control_id, "verdict": verdict},
                       seq)
            return rec

    def remediate(self, check_id: str, action: str, seq: object,
                  detail_digest: str = "") -> RemediationRecord:
        """Book one declared remediation against a failing check."""
        with self._lock:
            seq = self._claim(seq)
            try:
                check_id = _check_id("check_id", check_id)
                if check_id not in self._checks:
                    raise UnknownCheckError(f"unknown check: {check_id!r}")
                chk = self._checks[check_id]
                if chk.verdict not in (VERDICT_FAIL, VERDICT_PARTIAL):
                    raise CheckNotFailingError(
                        f"check {check_id!r} verdict {chk.verdict!r} is "
                        "not failing")
                if check_id in self._remediation_by_check:
                    raise AlreadyRemediatedError(
                        f"check already remediated: {check_id!r}")
                if action not in _ACTIONS:
                    raise BadActionError(
                        f"action {action!r} outside pinned vocabulary")
                detail_digest = _check_optional_digest("detail_digest",
                                                       detail_digest)
                remediation_id = f"rmd-{self._next_remediation}"
                self._next_remediation += 1
                rec = RemediationRecord(
                    remediation_id=remediation_id,
                    check_id=check_id,
                    action=action,
                    detail_digest=detail_digest,
                    seq=seq,
                    digest=_pin("remediation", check_id, action,
                                detail_digest),
                )
            except ComplianceError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            self._remediations[remediation_id] = rec
            self._remediation_by_check[check_id] = remediation_id
            self._emit(KIND_REMEDIATED,
                       {"remediation_id": remediation_id,
                        "check_id": check_id, "action": action},
                       seq)
            return rec

    # -- pure reads --------------------------------------------------

    def attest(self, framework_id: str, seq: object) -> AttestationReport:
        """Derive the compliance posture for one framework (pure read)."""
        with self._lock:
            _check_id("framework_id", framework_id)
            if framework_id not in self._frameworks:
                raise UnknownFrameworkError(
                    f"unknown framework: {framework_id!r}")
            _check_seq(seq)  # shape validated, never consumed
            ids = self._checks_by_framework.get(framework_id, [])
            n_checks = len(ids)
            n_passed = 0
            n_failed = 0
            n_remediated = 0
            for cid in ids:
                chk = self._checks[cid]
                if chk.verdict == VERDICT_PASS:
                    n_passed += 1
                elif chk.verdict in (VERDICT_FAIL, VERDICT_PARTIAL):
                    n_failed += 1
                    if cid in self._remediation_by_check:
                        n_remediated += 1
            unremediated = n_failed - n_remediated
            if n_checks == 0:
                posture = "not-assessed"
            elif unremediated > 0:
                posture = "non-compliant"
            else:
                posture = "compliant"
            return AttestationReport(
                framework_id=framework_id,
                posture=posture,
                n_checks=n_checks,
                n_passed=n_passed,
                n_failed=n_failed,
                n_remediated=n_remediated,
                seq=seq,
                digest=_pin("attestation", framework_id, posture, n_checks,
                            n_passed, n_failed, n_remediated),
            )

    def framework_record(self, framework_id: str,
                         seq: object) -> FrameworkRecord:
        """Pure read: one framework record."""
        with self._lock:
            _check_seq(seq)
            _check_id("framework_id", framework_id)
            if framework_id not in self._frameworks:
                raise UnknownFrameworkError(
                    f"unknown framework: {framework_id!r}")
            return self._frameworks[framework_id]

    def check_record(self, check_id: str, seq: object) -> CheckRecord:
        """Pure read: one check record."""
        with self._lock:
            _check_seq(seq)
            _check_id("check_id", check_id)
            if check_id not in self._checks:
                raise UnknownCheckError(f"unknown check: {check_id!r}")
            return self._checks[check_id]

    def framework_ids(self, seq: object) -> Tuple[str, ...]:
        """Pure read: registered framework ids, sorted."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._frameworks))

    def checks_for(self, framework_id: str,
                   seq: object) -> Tuple[str, ...]:
        """Pure read: check ids for one framework, insertion order."""
        with self._lock:
            _check_seq(seq)
            _check_id("framework_id", framework_id)
            if framework_id not in self._frameworks:
                raise UnknownFrameworkError(
                    f"unknown framework: {framework_id!r}")
            return tuple(self._checks_by_framework[framework_id])

    def audit_log(self, seq: object) -> Tuple[Dict[str, object], ...]:
        """Pure read: audit rows (no seq consumption, no new rows)."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: object) -> Dict[str, int]:
        """Pure read: ledger counts."""
        with self._lock:
            _check_seq(seq)
            return {
                "frameworks": len(self._frameworks),
                "checks": len(self._checks),
                "remediations": len(self._remediations),
                "rejected": sum(1 for row in self._audit
                                if row["kind"] == KIND_REJECTED),
            }


def main() -> None:
    """Self-check smoke run."""
    c = Compliance()
    c.register_framework("fw-1", KIND_SOC2, 1)
    c.check("fw-1", "CC6.1", VERDICT_PASS, 2)
    c.check("fw-1", "CC6.2", VERDICT_FAIL, 3)
    c.remediate("chk-2", ACTION_PATCH, 4)
    rep = c.attest("fw-1", 5)
    assert rep.posture == "compliant", rep.posture
    assert rep.verify("fw-1", "compliant", 2, 1, 1, 1)
    print("compliance OK: register, check, remediate, attest, pins, audit")


if __name__ == "__main__":
    main()
