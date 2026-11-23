#!/usr/bin/env python3
"""Regulatory — simulated registration and reporting bookkeeping.

This module provides a ledger interface for regulatory compliance
tasks — registering systems under a regulatory framework, filing
reports, and tracking compliance status.  It is deliberately
Simulated: it does not file real reports with any authority and
does not validate compliance — it books declared registration
and reporting decisions so they can be audited deterministically.

Conventions: frozen dataclasses, caller-controlled strictly
increasing integer seq numbers (failed mutations consume their seq),
no wall-clock, RLock-guarded, fail-closed error taxonomy,
stdlib-only, sha256: digest pins, audit.ndjson/1 events.

Use:

    reg = Regulatory()
    reg.register("agent-os-v1", "EU-AI-Act", 1)
    reg.report("agent-os-v1", "conformity-assessment", 2, outcome="submitted")
    print(reg.comply("agent-os-v1", 3))
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

__all__ = [
    "Regulatory",
    "RegulatoryError",
    "BadSystemError",
    "DuplicateSystemError",
    "UnknownSystemError",
    "BadFrameworkError",
    "BadReportError",
    "DuplicateReportError",
    "BadOutcomeError",
    "SeqOrderError",
    "AuditKindError",
    "regulatory_audit_event",
    "main",
]

VERSION = "regulatory.v1"
SCHEMA = "northstar.regulatory.v1"

FRAMEWORKS = frozenset({
    "EU-AI-Act",
    "US-EO-14110",
    "UK-Pro-Innovation",
    "China-GenAI-Measures",
    "Canada-AIDA",
    "Custom",
})

REPORT_KINDS = frozenset({
    "conformity-assessment",
    "incident-notification",
    "annual-report",
    "risk-assessment",
    "audit-finding",
    "registration-update",
})

REPORT_OUTCOMES = frozenset({
    "submitted",
    "accepted",
    "rejected",
    "pending-review",
    "withdrawn",
})


def _check_id(value: Any, what: str, exc) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise exc(f"bad {what} id: {value!r}")
    return value


def _digest_pin(*parts: str) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return "sha256:" + h.hexdigest()


class RegulatoryError(Exception):
    pass


class BadSystemError(RegulatoryError):
    pass


class DuplicateSystemError(RegulatoryError):
    pass


class UnknownSystemError(RegulatoryError):
    pass


class BadFrameworkError(RegulatoryError):
    pass


class BadReportError(RegulatoryError):
    pass


class DuplicateReportError(RegulatoryError):
    pass


class BadOutcomeError(RegulatoryError):
    pass


class SeqOrderError(RegulatoryError):
    pass


class AuditKindError(RegulatoryError):
    pass


@dataclass(frozen=True)
class RegistrationRecord:
    system_id: str
    framework: str
    seq: int
    digest: str
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "framework": self.framework,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ReportRecord:
    report_id: str
    system_id: str
    kind: str
    outcome: str
    seq: int
    digest: str
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "system_id": self.system_id,
            "kind": self.kind,
            "outcome": self.outcome,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ComplianceView:
    system_id: str
    framework: str
    reports_submitted: int
    reports_accepted: int
    compliant: bool
    seq: int
    digest: str
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "framework": self.framework,
            "reports_submitted": self.reports_submitted,
            "reports_accepted": self.reports_accepted,
            "compliant": self.compliant,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
        }


AUDIT_KINDS = frozenset({
    "registered",
    "reported",
    "compliance-checked",
    "rejected",
})


def regulatory_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build an audit.ndjson/1 row.  Raw payloads never cross the boundary."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise SeqOrderError(f"bad audit seq: {seq!r}")
    banned = {"payload", "text", "raw", "data", "value"}
    for key in details:
        if key in banned:
            raise AuditKindError(f"banned audit key: {key!r}")
    row = {"audit_seq": seq, "kind": f"regulatory.{kind}", "schema": SCHEMA}
    row.update(details)
    return row


class Regulatory:
    """Simulated regulatory registration and reporting ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._registrations: Dict[str, RegistrationRecord] = {}
        self._reports: Dict[str, ReportRecord] = {}
        self._system_reports: Dict[str, List[str]] = {}
        self._report_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # --- seq discipline -------------------------------------------------
    def _claim(self, seq: int) -> None:
        if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
            raise SeqOrderError(f"bad seq: {seq!r}")
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not after {self._seq}")
        self._seq = seq

    def _burn(self, seq: int, op: str, **details: Any) -> None:
        # seq was already claimed before the error; just book the rejected row.
        self._audit.append(
            regulatory_audit_event("rejected", seq, op=op, **details)
        )

    def _audit_row(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(regulatory_audit_event(kind, seq, **details))

    # --- API ------------------------------------------------------------
    def register(self, system_id: str, framework: str, seq: int) -> RegistrationRecord:
        """Declare a system under a regulatory framework (simulated)."""
        with self._lock:
            try:
                self._claim(seq)
                _check_id(system_id, "system", BadSystemError)
                if framework not in FRAMEWORKS:
                    raise BadFrameworkError(f"unknown framework: {framework!r}")
                if system_id in self._registrations:
                    raise DuplicateSystemError(f"already registered: {system_id!r}")
                digest = _digest_pin(system_id, framework, str(seq), VERSION)
                record = RegistrationRecord(
                    system_id=system_id,
                    framework=framework,
                    seq=seq,
                    digest=digest,
                )
                self._registrations[system_id] = record
                self._system_reports[system_id] = []
                self._audit_row(
                    "registered",
                    seq,
                    system_id=system_id,
                    framework=framework,
                    digest=digest,
                )
                return record
            except RegulatoryError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, "register", error=type(exc).__name__)
                raise

    def report(
        self,
        system_id: str,
        kind: str,
        seq: int,
        outcome: str = "submitted",
    ) -> ReportRecord:
        """Book a filed report for a registered system (simulated)."""
        with self._lock:
            try:
                self._claim(seq)
                if system_id not in self._registrations:
                    raise UnknownSystemError(f"not registered: {system_id!r}")
                if kind not in REPORT_KINDS:
                    raise BadReportError(f"unknown report kind: {kind!r}")
                if outcome not in REPORT_OUTCOMES:
                    raise BadOutcomeError(f"unknown outcome: {outcome!r}")
                self._report_counter += 1
                report_id = f"rep-{self._report_counter}"
                digest = _digest_pin(
                    report_id, system_id, kind, outcome, str(seq), VERSION
                )
                record = ReportRecord(
                    report_id=report_id,
                    system_id=system_id,
                    kind=kind,
                    outcome=outcome,
                    seq=seq,
                    digest=digest,
                )
                self._reports[report_id] = record
                self._system_reports[system_id].append(report_id)
                self._audit_row(
                    "reported",
                    seq,
                    report_id=report_id,
                    system_id=system_id,
                    report_kind=kind,
                    outcome=outcome,
                    digest=digest,
                )
                return record
            except RegulatoryError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, "report", error=type(exc).__name__)
                raise

    def comply(self, system_id: str, seq: int) -> ComplianceView:
        """Pure read view: compliance posture of a registered system."""
        with self._lock:
            if system_id not in self._registrations:
                raise UnknownSystemError(f"not registered: {system_id!r}")
            reg = self._registrations[system_id]
            report_ids = self._system_reports[system_id]
            submitted = len(report_ids)
            accepted = sum(
                1
                for rid in report_ids
                if self._reports[rid].outcome in ("submitted", "accepted")
            )
            rejected = sum(
                1
                for rid in report_ids
                if self._reports[rid].outcome == "rejected"
            )
            compliant = submitted > 0 and rejected == 0
            digest = _digest_pin(
                system_id,
                str(submitted),
                str(accepted),
                str(compliant),
                str(seq),
                VERSION,
            )
            self._audit_row(
                "compliance-checked",
                seq,
                system_id=system_id,
                reports_submitted=submitted,
                reports_accepted=accepted,
                compliant=compliant,
                digest=digest,
            )
            return ComplianceView(
                system_id=system_id,
                framework=reg.framework,
                reports_submitted=submitted,
                reports_accepted=accepted,
                compliant=compliant,
                seq=seq,
                digest=digest,
            )

    # --- views ----------------------------------------------------------
    def registration(self, system_id: str) -> RegistrationRecord:
        with self._lock:
            if system_id not in self._registrations:
                raise UnknownSystemError(f"not registered: {system_id!r}")
            return self._registrations[system_id]

    def system_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._registrations))

    def report_record(self, report_id: str) -> ReportRecord:
        with self._lock:
            if report_id not in self._reports:
                raise BadReportError(f"unknown report: {report_id!r}")
            return self._reports[report_id]

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "systems": len(self._registrations),
                "reports": len(self._reports),
                "seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    reg = Regulatory()
    reg.register("agent-os-v1", "EU-AI-Act", 1)
    reg.report("agent-os-v1", "conformity-assessment", 2)
    view = reg.comply("agent-os-v1", 3)
    assert view.compliant
    print("regulatory OK: register, report, comply, pins, audit")


if __name__ == "__main__":
    main()
