"""Penetration testing: engagement decision ledger, Simulated.

Research note: penetration testing (black / gray / white box, PTES / OWASP
testing guide / MITRE ATT&CK) runs a structured campaign against a target -
reconnaissance, scanning, exploitation, post-exploitation - and then
remediates the findings. The industry discipline is not the exploitation
itself; it is the *decision trail*: what was in scope, what was found, what
was attempted, what it proved, and how each finding was closed. A booked
"finding" is never proof the target is vulnerable; it is proof a declared
scan ran and a declared outcome was recorded.

This module is that decision ledger for penetration-test engagements,
deliberately distinct from its siblings:

- ``vulnerability_scanner.py`` - (sibling layer, scan primitives)
- ``pen_testing`` owns the engagement lifecycle instead:

* **register_target()** - declare one target as in scope for the
  engagement.
* **scan()** - book one declared scan against a registered target (pinned
  scan-kind, finding, and severity vocabularies). Findings are data, never
  proof of vulnerability.
* **exploit()** - book one declared exploitation attempt against a scan
  that reported an actionable finding. Impact is host-declared data, never
  proof of compromise.
* **remediate()** - book one declared remediation action against an
  un-remediated actionable scan (pinned action vocabulary).
* **verify()** - pure read view: re-walks digest pins and reports the
  target's engagement state as data.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``pen-testing.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module launches no scans, runs no exploits, and cannot
prove a target is vulnerable or clean. All findings and impacts are
host-declared GIGO booked under digest pins; raw payloads, shells,
credentials, and target bytes never cross the module boundary.
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
PEN_TESTING_VERSION = "pen-testing.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.pen-testing.v1"

#: Pinned scan-kind vocabulary (declared, never executed).
SCAN_KINDS = (
    "network",
    "web",
    "api",
    "config",
    "dependency",
)

#: Pinned finding vocabulary. ``none`` means "no actionable finding booked".
#: Findings are data, never proof of vulnerability.
FINDINGS = (
    "none",
    "open-port",
    "weak-auth",
    "unpatched-cve",
    "misconfig",
    "exposed-data",
)

#: Pinned severity vocabulary (host-declared, booked as data).
SEVERITIES = (
    "info",
    "low",
    "medium",
    "high",
    "critical",
)

#: Pinned exploitation-technique vocabulary (declared, never executed).
TECHNIQUES = (
    "sql-injection",
    "xss",
    "ssrf",
    "privilege-escalation",
    "rce",
    "csrf",
    "credential-stuffing",
)

#: Pinned impact vocabulary. Impact is host-declared data, never proof of
#: compromise.
IMPACTS = (
    "none",
    "limited",
    "full",
)

#: Pinned remediation-action vocabulary (declared, never executed).
ACTIONS = (
    "patch",
    "reconfigure",
    "rotate-credential",
    "isolate",
    "accept-risk",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "target-registered",
    "scan-recorded",
    "exploited",
    "remediated",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "payload",
        "shell",
        "exploit_code",
        "response",
        "password",
        "credential",
        "cookie",
        "token",
        "secret",
        "raw",
        "text",
        "content",
        "data",
        "value",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PenTestingError(Exception):
    """Base error for pen-testing ledger misuse."""


class BadTargetError(PenTestingError):
    """Malformed target id."""


class DuplicateTargetError(PenTestingError):
    """Target id already registered."""


class UnknownTargetError(PenTestingError):
    """Target id not registered."""


class BadDigestError(PenTestingError):
    """Malformed sha256: digest pin."""


class BadScanKindError(PenTestingError):
    """Unknown scan kind."""


class BadFindingError(PenTestingError):
    """Unknown finding."""


class BadSeverityError(PenTestingError):
    """Unknown severity."""


class BadTechniqueError(PenTestingError):
    """Unknown exploitation technique."""


class BadImpactError(PenTestingError):
    """Unknown impact."""


class BadActionError(PenTestingError):
    """Unknown remediation action."""


class UnknownScanError(PenTestingError):
    """Scan id not booked."""


class UnknownExploitError(PenTestingError):
    """Exploit id not booked."""


class UnknownRemediationError(PenTestingError):
    """Remediation id not booked."""


class ExploitStateError(PenTestingError):
    """Exploit preconditions not met (clean scan, or already exploited)."""


class RemediationStateError(PenTestingError):
    """Remediation preconditions not met (clean scan, or already remediated)."""


class SeqOrderError(PenTestingError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(PenTestingError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Validators / pins
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadTargetError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
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
class TargetRecord:
    target_id: str
    target_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "target_id": self.target_id,
            "target_digest": self.target_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "target_id": self.target_id,
                "target_digest": self.target_digest,
            }
        )


@dataclass(frozen=True)
class ScanRecord:
    scan_id: str
    target_id: str
    scan_kind: str
    finding: str
    severity: str
    evidence_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "scan_id": self.scan_id,
            "target_id": self.target_id,
            "scan_kind": self.scan_kind,
            "finding": self.finding,
            "severity": self.severity,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "scan_id": self.scan_id,
                "target_id": self.target_id,
                "scan_kind": self.scan_kind,
                "finding": self.finding,
                "severity": self.severity,
                "evidence_digest": self.evidence_digest,
            }
        )


@dataclass(frozen=True)
class ExploitRecord:
    exploit_id: str
    target_id: str
    scan_id: str
    technique: str
    impact: str
    evidence_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "exploit_id": self.exploit_id,
            "target_id": self.target_id,
            "scan_id": self.scan_id,
            "technique": self.technique,
            "impact": self.impact,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "exploit_id": self.exploit_id,
                "target_id": self.target_id,
                "scan_id": self.scan_id,
                "technique": self.technique,
                "impact": self.impact,
                "evidence_digest": self.evidence_digest,
            }
        )


@dataclass(frozen=True)
class RemediationRecord:
    remediation_id: str
    target_id: str
    scan_id: str
    action: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "remediation_id": self.remediation_id,
            "target_id": self.target_id,
            "scan_id": self.scan_id,
            "action": self.action,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "remediation_id": self.remediation_id,
                "target_id": self.target_id,
                "scan_id": self.scan_id,
                "action": self.action,
            }
        )


@dataclass(frozen=True)
class VerifyReport:
    target_id: str
    n_scans: int
    n_exploits: int
    n_remediations: int
    actionable_scans: int
    remediated: bool
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "target_id": self.target_id,
            "n_scans": self.n_scans,
            "n_exploits": self.n_exploits,
            "n_remediations": self.n_remediations,
            "actionable_scans": self.actionable_scans,
            "remediated": self.remediated,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "target_id": self.target_id,
                "n_scans": self.n_scans,
                "n_exploits": self.n_exploits,
                "n_remediations": self.n_remediations,
                "actionable_scans": self.actionable_scans,
                "remediated": self.remediated,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def pen_testing_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the pen-testing ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class PenTesting:
    """Penetration-test engagement decision ledger (Simulated).

    ``register_target()`` / ``scan()`` / ``exploit()`` / ``remediate()``
    mutate the ledger and consume caller seqs; ``verify()`` and all views
    are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._targets: Dict[str, TargetRecord] = {}
        self._scans: Dict[str, ScanRecord] = {}
        self._target_scans: Dict[str, List[str]] = {}
        self._exploits: Dict[str, ExploitRecord] = {}
        self._exploit_of_scan: Dict[str, str] = {}
        self._remediations: Dict[str, RemediationRecord] = {}
        self._remediation_of_scan: Dict[str, str] = {}
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0
        self._scn_counter = 0
        self._xpl_counter = 0
        self._rmd_counter = 0

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = pen_testing_audit_event(
                "rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            pen_testing_audit_event(audit_kind, seq, **details))

    # -- register_target -----------------------------------------------------

    def register_target(
        self, target_id: str, seq: int, target_digest: str = ""
    ) -> TargetRecord:
        """Declare one target as in scope for the engagement."""
        with self._lock:
            try:
                self._claim(seq)
            except PenTestingError:
                raise
            try:
                _require_id(target_id, "target_id")
                if target_digest:
                    _require_digest(target_digest, "target_digest")
                else:
                    target_digest = "sha256:" + "00" * 32
                if target_id in self._targets:
                    raise DuplicateTargetError(
                        f"target already registered: {target_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "target_id": target_id,
                        "target_digest": target_digest,
                    }
                )
                record = TargetRecord(
                    target_id=target_id,
                    target_digest=target_digest,
                    digest=digest,
                )
                self._targets[target_id] = record
                self._target_scans[target_id] = []
                self._emit("target-registered", seq, target_id=target_id)
                return record
            except PenTestingError:
                self._burn(seq, "register_target")
                raise

    # -- scan ----------------------------------------------------------------

    def scan(
        self,
        target_id: str,
        seq: int,
        scan_kind: str = "network",
        finding: str = "none",
        severity: str = "info",
        evidence_digest: str = "",
    ) -> ScanRecord:
        """Book one declared scan. The finding is data, never proof."""
        with self._lock:
            try:
                self._claim(seq)
            except PenTestingError:
                raise
            try:
                if target_id not in self._targets:
                    raise UnknownTargetError(f"unknown target: {target_id!r}")
                if scan_kind not in SCAN_KINDS:
                    raise BadScanKindError(
                        f"scan_kind must be one of {SCAN_KINDS}")
                if finding not in FINDINGS:
                    raise BadFindingError(f"finding must be one of {FINDINGS}")
                if severity not in SEVERITIES:
                    raise BadSeverityError(
                        f"severity must be one of {SEVERITIES}")
                if evidence_digest:
                    _require_digest(evidence_digest, "evidence_digest")
                else:
                    evidence_digest = "sha256:" + "00" * 32
                self._scn_counter += 1
                scan_id = f"scn-{self._scn_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "scan_id": scan_id,
                        "target_id": target_id,
                        "scan_kind": scan_kind,
                        "finding": finding,
                        "severity": severity,
                        "evidence_digest": evidence_digest,
                    }
                )
                record = ScanRecord(
                    scan_id=scan_id,
                    target_id=target_id,
                    scan_kind=scan_kind,
                    finding=finding,
                    severity=severity,
                    evidence_digest=evidence_digest,
                    digest=digest,
                )
                self._scans[scan_id] = record
                self._target_scans[target_id].append(scan_id)
                self._emit(
                    "scan-recorded", seq, scan_id=scan_id,
                    target_id=target_id, finding=finding,
                )
                return record
            except PenTestingError:
                self._burn(seq, "scan")
                raise

    # -- exploit ---------------------------------------------------------------

    def exploit(
        self,
        scan_id: str,
        seq: int,
        technique: str = "ssrf",
        impact: str = "limited",
        evidence_digest: str = "",
    ) -> ExploitRecord:
        """Book one declared exploitation attempt against an actionable scan.

        Impact is host-declared data, never proof of compromise. One
        exploit is booked per scan: a second exploit of the same scan is
        refused fail-closed.
        """
        with self._lock:
            try:
                self._claim(seq)
            except PenTestingError:
                raise
            try:
                scan = self._scans.get(scan_id)
                if scan is None:
                    raise UnknownScanError(f"unknown scan: {scan_id!r}")
                if scan.finding == "none":
                    raise ExploitStateError(
                        f"scan {scan_id!r} reported no actionable finding")
                if scan_id in self._exploit_of_scan:
                    raise ExploitStateError(
                        f"scan already exploited: {scan_id!r}")
                if technique not in TECHNIQUES:
                    raise BadTechniqueError(
                        f"technique must be one of {TECHNIQUES}")
                if impact not in IMPACTS:
                    raise BadImpactError(f"impact must be one of {IMPACTS}")
                if evidence_digest:
                    _require_digest(evidence_digest, "evidence_digest")
                else:
                    evidence_digest = "sha256:" + "00" * 32
                self._xpl_counter += 1
                exploit_id = f"xpl-{self._xpl_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "exploit_id": exploit_id,
                        "target_id": scan.target_id,
                        "scan_id": scan_id,
                        "technique": technique,
                        "impact": impact,
                        "evidence_digest": evidence_digest,
                    }
                )
                record = ExploitRecord(
                    exploit_id=exploit_id,
                    target_id=scan.target_id,
                    scan_id=scan_id,
                    technique=technique,
                    impact=impact,
                    evidence_digest=evidence_digest,
                    digest=digest,
                )
                self._exploits[exploit_id] = record
                self._exploit_of_scan[scan_id] = exploit_id
                self._emit(
                    "exploited", seq, exploit_id=exploit_id,
                    scan_id=scan_id, technique=technique, impact=impact,
                )
                return record
            except PenTestingError:
                self._burn(seq, "exploit")
                raise

    # -- remediate ---------------------------------------------------------------

    def remediate(
        self,
        scan_id: str,
        seq: int,
        action: str = "patch",
    ) -> RemediationRecord:
        """Book one declared remediation against an un-remediated finding.

        A scan with finding ``none`` needs no remediation and is refused;
        a scan that already carries a remediation is refused fail-closed.
        Remediation does not require a prior exploit: the finding may be
        closed directly.
        """
        with self._lock:
            try:
                self._claim(seq)
            except PenTestingError:
                raise
            try:
                scan = self._scans.get(scan_id)
                if scan is None:
                    raise UnknownScanError(f"unknown scan: {scan_id!r}")
                if scan.finding == "none":
                    raise RemediationStateError(
                        f"scan {scan_id!r} reported no actionable finding")
                if scan_id in self._remediation_of_scan:
                    raise RemediationStateError(
                        f"scan already remediated: {scan_id!r}")
                if action not in ACTIONS:
                    raise BadActionError(f"action must be one of {ACTIONS}")
                self._rmd_counter += 1
                remediation_id = f"rmd-{self._rmd_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "remediation_id": remediation_id,
                        "target_id": scan.target_id,
                        "scan_id": scan_id,
                        "action": action,
                    }
                )
                record = RemediationRecord(
                    remediation_id=remediation_id,
                    target_id=scan.target_id,
                    scan_id=scan_id,
                    action=action,
                    digest=digest,
                )
                self._remediations[remediation_id] = record
                self._remediation_of_scan[scan_id] = remediation_id
                self._emit(
                    "remediated", seq, remediation_id=remediation_id,
                    scan_id=scan_id, action=action,
                )
                return record
            except PenTestingError:
                self._burn(seq, "remediate")
                raise

    # -- verify (pure read) --------------------------------------------------

    def verify(self, target_id: str, seq: int) -> VerifyReport:
        """Pure read: re-walk digest pins, report engagement state as data."""
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("verify seq must be a non-negative int")
            target = self._targets.get(target_id)
            if target is None:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            integrity_ok = target.verify()
            scan_ids = self._target_scans.get(target_id, [])
            scans = [self._scans[sid] for sid in scan_ids]
            for scan in scans:
                if not scan.verify():
                    integrity_ok = False
            n_exploits = sum(
                1 for sid in scan_ids if sid in self._exploit_of_scan)
            n_remediations = sum(
                1 for sid in scan_ids if sid in self._remediation_of_scan)
            actionable = [
                scan for scan in scans if scan.finding != "none"]
            remediated = all(
                scan.scan_id in self._remediation_of_scan
                for scan in actionable
            )
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "target_id": target_id,
                    "n_scans": len(scans),
                    "n_exploits": n_exploits,
                    "n_remediations": n_remediations,
                    "actionable_scans": len(actionable),
                    "remediated": remediated,
                    "integrity_ok": integrity_ok,
                }
            )
            return VerifyReport(
                target_id=target_id,
                n_scans=len(scans),
                n_exploits=n_exploits,
                n_remediations=n_remediations,
                actionable_scans=len(actionable),
                remediated=remediated,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def target_record(self, target_id: str, seq: int) -> TargetRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._targets.get(target_id)
            if record is None:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            return record

    def scan_record(self, scan_id: str, seq: int) -> ScanRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._scans.get(scan_id)
            if record is None:
                raise UnknownScanError(f"unknown scan: {scan_id!r}")
            return record

    def exploit_record(self, exploit_id: str, seq: int) -> ExploitRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._exploits.get(exploit_id)
            if record is None:
                raise UnknownExploitError(f"unknown exploit: {exploit_id!r}")
            return record

    def remediation_record(self, remediation_id: str,
                           seq: int) -> RemediationRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._remediations.get(remediation_id)
            if record is None:
                raise UnknownRemediationError(
                    f"unknown remediation: {remediation_id!r}")
            return record

    def target_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._targets))

    def scan_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._scans))

    def scans_for(self, target_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if target_id not in self._targets:
                raise UnknownTargetError(f"unknown target: {target_id!r}")
            return tuple(self._target_scans.get(target_id, ()))

    def is_remediated(self, scan_id: str, seq: int) -> bool:
        with self._lock:
            self._view_seq_ok(seq)
            if scan_id not in self._scans:
                raise UnknownScanError(f"unknown scan: {scan_id!r}")
            return scan_id in self._remediation_of_scan

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "targets": len(self._targets),
                "scans": len(self._scans),
                "exploits": len(self._exploits),
                "remediations": len(self._remediations),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }


def main() -> None:
    pt = PenTesting()
    rec = pt.register_target("web-01", 1)
    scan = pt.scan("web-01", 2, scan_kind="web", finding="unpatched-cve",
                   severity="high")
    xpl = pt.exploit(scan.scan_id, 3, technique="sql-injection", impact="limited")
    assert xpl.scan_id == scan.scan_id
    rmd = pt.remediate(scan.scan_id, 4, action="patch")
    report = pt.verify("web-01", 0)
    assert rec.verify() and scan.verify() and xpl.verify() and rmd.verify()
    assert report.verify() and report.remediated
    assert report.integrity_ok
    assert report.n_scans == 1 and report.n_exploits == 1
    assert report.n_remediations == 1 and report.actionable_scans == 1
    print(
        "pen-testing OK: register, scan, exploit, remediate, verify, "
        "pins, audit"
    )


if __name__ == "__main__":
    main()
