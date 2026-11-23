"""Abuse reporter: report / triage / resolve bookkeeping (simulated).

Research note: every large platform converges on the same abuse-handling
lifecycle — a user files a *report*, a trust-and-safety queue *triages*
it (priority + assignee), and a reviewer *resolves* it with a pinned
action. The shape is codified in the Santa Clara Principles (notice,
appeal), the DSA transparency-reporting duties, and the public
transparency reports of Meta, Google, and X:

* **Report** — the reporter names a *subject* (account/content id) and a
  *category* from a pinned vocabulary. The ledger mints the report and
  pins a digest over (report_id, reporter, subject, category,
  description digest, seqs). The same reporter may not hold two *open*
  reports against the same subject+category (anti-spam ledger rule).
* **Triage** — a triager moves the report ``open -> triaged`` and pins a
  priority (low/medium/high/urgent) plus an assignee. Triage is a
  one-way gate: only ``open`` reports can be triaged.
* **Resolve** — a reviewer moves the report ``triaged -> resolved``
  with an action from a pinned vocabulary (no-violation,
  warning-issued, content-removed, account-suspended, account-banned,
  escalated-law-enforcement). Resolution is terminal.

Fail-closed rules:

* Categories, priorities, and actions come from pinned vocabularies;
  anything else is refused.
* Mutation seqs must strictly increase per manager (``SeqOrderError``);
  failed mutations consume their seq (batch-21 discipline) so the audit
  trail stays totally ordered.
* Report descriptions are capped at ``MAX_DESCRIPTION_CHARS``; evidence
  items are host-reported refs booked as digest-pinned
  ``EvidenceItem``s — the raw evidence text never crosses the audit
  boundary.
* ``triage()`` on a non-``open`` report and ``resolve()`` on a
  non-``triaged`` report raise ``InvalidStateError``; a second
  ``resolve()`` raises ``TerminalReportError``.
* Audit events carry ids + digest pins only.

Honest scope: this books *reported* abuse events. It cannot verify that
a violation actually occurred, cannot observe the reported content, and
the triage priority is a bookkeeping label, not a risk judgment —
production deployments pair this ledger with real content review and
an appeals path. Deterministic with an explicit ``seed=``.

Version pin: abuse-reporter.v1
Schema pin: northstar.abuse-reporter.v1
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


ABUSE_REPORTER_VERSION = "abuse-reporter.v1"
SCHEMA_PIN = "northstar.abuse-reporter.v1"

CATEGORIES: Tuple[str, ...] = (
    "spam",
    "harassment",
    "hate-speech",
    "impersonation",
    "fraud",
    "violent-content",
    "self-harm",
    "child-safety",
    "copyright",
    "malware",
    "other",
)

PRIORITIES: Tuple[str, ...] = ("low", "medium", "high", "urgent")

ACTIONS: Tuple[str, ...] = (
    "no-violation",
    "warning-issued",
    "content-removed",
    "account-suspended",
    "account-banned",
    "escalated-law-enforcement",
)

MAX_DESCRIPTION_CHARS = 4000
MAX_ID_CHARS = 256
MAX_EVIDENCE_ITEMS = 32


class AbuseReporterError(Exception):
    """Base class for abuse reporter errors."""


class BadReportError(AbuseReporterError):
    """Report inputs failed fail-closed validation."""


class UnknownReportError(AbuseReporterError):
    """No such report id."""


class DuplicateReportError(AbuseReporterError):
    """Reporter already has an open report on this subject+category."""


class InvalidStateError(AbuseReporterError):
    """The report is not in the state this transition requires."""


class TerminalReportError(AbuseReporterError):
    """The report is resolved; no further transitions are possible."""


class BadTriageError(AbuseReporterError):
    """Triage inputs failed fail-closed validation."""


class BadResolutionError(AbuseReporterError):
    """Resolution inputs failed fail-closed validation."""


class SeqOrderError(AbuseReporterError):
    """Mutation seq did not strictly increase."""


def _is_int_seq(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadReportError(f"{field} must be a non-empty string")
    if len(value) > MAX_ID_CHARS:
        raise BadReportError(f"{field} exceeds {MAX_ID_CHARS} chars")
    return value


@dataclass(frozen=True)
class EvidenceItem:
    """A digest-pinned reference to host-reported evidence."""

    kind: str
    digest: str

    def verify(self, raw: str) -> bool:
        return hmac.compare_digest(
            self.digest,
            "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        )


@dataclass(frozen=True)
class AbuseReport:
    """A filed abuse report."""

    report_id: str
    reporter_id: str
    subject_id: str
    category: str
    description: str
    evidence: Tuple[EvidenceItem, ...]
    state: str
    seq: int
    prev_digest: str
    digest: str

    def verify(self, manager: "AbuseReporter") -> bool:
        return hmac.compare_digest(
            self.digest, manager._report_digest(self)
        )


@dataclass(frozen=True)
class TriageDecision:
    """A triage decision pinning priority and assignee."""

    triage_id: str
    report_id: str
    triager_id: str
    priority: str
    assignee: str
    seq: int
    digest: str

    def verify(self, manager: "AbuseReporter") -> bool:
        return hmac.compare_digest(
            self.digest, manager._triage_digest(self)
        )


@dataclass(frozen=True)
class ResolutionRecord:
    """A terminal resolution of a report."""

    resolution_id: str
    report_id: str
    resolver_id: str
    action: str
    note: str
    seq: int
    digest: str

    def verify(self, manager: "AbuseReporter") -> bool:
        return hmac.compare_digest(
            self.digest, manager._resolution_digest(self)
        )


class AbuseReporter:
    """Deterministic abuse report / triage / resolve ledger."""

    def __init__(self, seed: Optional[bytes] = None) -> None:
        self._salt = seed if seed is not None else secrets.token_bytes(16)
        self._lock = threading.RLock()
        self._seq = -1
        self._next_report = 0
        self._next_triage = 0
        self._next_resolution = 0
        self._reports: Dict[str, AbuseReport] = {}
        self._triages: Dict[str, TriageDecision] = {}
        self._resolutions: Dict[str, ResolutionRecord] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- digests ----------------------------------------------------

    def _pin(self, *parts: Any) -> str:
        payload = jcs_canonical_json(
            {"salt": self._salt.hex(), "parts": list(parts)}
        )
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def _report_digest(self, report: AbuseReport) -> str:
        return self._pin(
            "report",
            report.report_id,
            report.reporter_id,
            report.subject_id,
            report.category,
            hashlib.sha256(report.description.encode("utf-8")).hexdigest(),
            [e.digest for e in report.evidence],
            report.state,
            report.seq,
            report.prev_digest,
        )

    def _triage_digest(self, triage: TriageDecision) -> str:
        return self._pin(
            "triage",
            triage.triage_id,
            triage.report_id,
            triage.triager_id,
            triage.priority,
            triage.assignee,
            triage.seq,
        )

    def _resolution_digest(self, resolution: ResolutionRecord) -> str:
        return self._pin(
            "resolution",
            resolution.resolution_id,
            resolution.report_id,
            resolution.resolver_id,
            resolution.action,
            hashlib.sha256(resolution.note.encode("utf-8")).hexdigest(),
            resolution.seq,
        )

    # -- internals --------------------------------------------------

    def _take_seq(self, seq: int) -> None:
        if not _is_int_seq(seq):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _audit_event(self, kind: str, **detail: Any) -> None:
        self._audit.append(
            abuse_reporter_audit_event(
                kind, {"seq": self._seq, **detail}
            )
        )

    # -- API --------------------------------------------------------

    def report(
        self,
        reporter_id: str,
        subject_id: str,
        category: str,
        description: str,
        seq: int,
        evidence: Tuple[str, ...] = (),
    ) -> AbuseReport:
        """File a new abuse report (state ``open``)."""
        with self._lock:
            self._take_seq(seq)
            try:
                reporter_id = _check_id(reporter_id, "reporter_id")
                subject_id = _check_id(subject_id, "subject_id")
                if category not in CATEGORIES:
                    raise BadReportError(f"unknown category: {category!r}")
                if not isinstance(description, str) or not description:
                    raise BadReportError("description must be non-empty")
                if len(description) > MAX_DESCRIPTION_CHARS:
                    raise BadReportError(
                        f"description exceeds {MAX_DESCRIPTION_CHARS} chars"
                    )
                if not isinstance(evidence, (tuple, list)):
                    raise BadReportError("evidence must be a tuple/list")
                if len(evidence) > MAX_EVIDENCE_ITEMS:
                    raise BadReportError("too many evidence items")
                items: List[EvidenceItem] = []
                for i, raw in enumerate(evidence):
                    if not isinstance(raw, str) or not raw:
                        raise BadReportError(
                            f"evidence[{i}] must be a non-empty string"
                        )
                    items.append(
                        EvidenceItem(
                            kind="ref",
                            digest="sha256:"
                            + hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                        )
                    )
                for existing in self._reports.values():
                    if (
                        existing.state == "open"
                        and existing.reporter_id == reporter_id
                        and existing.subject_id == subject_id
                        and existing.category == category
                    ):
                        raise DuplicateReportError(
                            "reporter already has an open report "
                            "on this subject+category"
                        )
                self._next_report += 1
                report_id = f"abr-{self._next_report}"
                prev = (
                    self._audit[-1]["payload"].get("digest")
                    if self._audit
                    else None
                ) or ("sha256:" + "00" * 32)
                record = AbuseReport(
                    report_id=report_id,
                    reporter_id=reporter_id,
                    subject_id=subject_id,
                    category=category,
                    description=description,
                    evidence=tuple(items),
                    state="open",
                    seq=seq,
                    prev_digest=prev,
                    digest="",
                )
                record = AbuseReport(
                    **{**record.__dict__, "digest": self._report_digest(record)}
                )
                self._reports[report_id] = record
                self._audit_event(
                    "reported",
                    report_id=report_id,
                    reporter_id=reporter_id,
                    subject_id=subject_id,
                    category=category,
                    digest=record.digest,
                )
                return record
            except AbuseReporterError:
                self._audit_event("rejected", op="report")
                raise

    def triage(
        self,
        report_id: str,
        triager_id: str,
        seq: int,
        priority: str,
        assignee: str,
    ) -> TriageDecision:
        """Move a report ``open -> triaged`` with priority + assignee."""
        with self._lock:
            self._take_seq(seq)
            try:
                report = self._reports.get(report_id)
                if report is None:
                    raise UnknownReportError(f"unknown report: {report_id!r}")
                if report.state == "resolved":
                    raise TerminalReportError("report is resolved")
                if report.state != "open":
                    raise InvalidStateError(
                        f"report is {report.state}, expected open"
                    )
                triager_id = _check_id(triager_id, "triager_id")
                assignee = _check_id(assignee, "assignee")
                if priority not in PRIORITIES:
                    raise BadTriageError(f"unknown priority: {priority!r}")
                self._next_triage += 1
                triage_id = f"trg-{self._next_triage}"
                decision = TriageDecision(
                    triage_id=triage_id,
                    report_id=report_id,
                    triager_id=triager_id,
                    priority=priority,
                    assignee=assignee,
                    seq=seq,
                    digest="",
                )
                decision = TriageDecision(
                    **{**decision.__dict__,
                       "digest": self._triage_digest(decision)}
                )
                self._triages[triage_id] = decision
                updated = AbuseReport(
                    **{**report.__dict__, "state": "triaged"}
                )
                updated = AbuseReport(
                    **{**updated.__dict__,
                       "digest": self._report_digest(updated)}
                )
                self._reports[report_id] = updated
                self._audit_event(
                    "triaged",
                    triage_id=triage_id,
                    report_id=report_id,
                    priority=priority,
                    assignee=assignee,
                    digest=decision.digest,
                )
                return decision
            except AbuseReporterError:
                self._audit_event("rejected", op="triage")
                raise

    def resolve(
        self,
        report_id: str,
        resolver_id: str,
        seq: int,
        action: str,
        note: str = "",
    ) -> ResolutionRecord:
        """Move a report ``triaged -> resolved`` (terminal)."""
        with self._lock:
            self._take_seq(seq)
            try:
                report = self._reports.get(report_id)
                if report is None:
                    raise UnknownReportError(f"unknown report: {report_id!r}")
                if report.state == "resolved":
                    raise TerminalReportError("report already resolved")
                if report.state != "triaged":
                    raise InvalidStateError(
                        f"report is {report.state}, expected triaged"
                    )
                resolver_id = _check_id(resolver_id, "resolver_id")
                if action not in ACTIONS:
                    raise BadResolutionError(f"unknown action: {action!r}")
                if not isinstance(note, str):
                    raise BadResolutionError("note must be a string")
                if len(note) > MAX_DESCRIPTION_CHARS:
                    raise BadResolutionError("note too long")
                self._next_resolution += 1
                resolution_id = f"res-{self._next_resolution}"
                resolution = ResolutionRecord(
                    resolution_id=resolution_id,
                    report_id=report_id,
                    resolver_id=resolver_id,
                    action=action,
                    note=note,
                    seq=seq,
                    digest="",
                )
                resolution = ResolutionRecord(
                    **{**resolution.__dict__,
                       "digest": self._resolution_digest(resolution)}
                )
                self._resolutions[resolution_id] = resolution
                updated = AbuseReport(
                    **{**report.__dict__, "state": "resolved"}
                )
                updated = AbuseReport(
                    **{**updated.__dict__,
                       "digest": self._report_digest(updated)}
                )
                self._reports[report_id] = updated
                self._audit_event(
                    "resolved",
                    resolution_id=resolution_id,
                    report_id=report_id,
                    action=action,
                    digest=resolution.digest,
                )
                return resolution
            except AbuseReporterError:
                self._audit_event("rejected", op="resolve")
                raise

    # -- views ------------------------------------------------------

    def get_report(self, report_id: str) -> AbuseReport:
        with self._lock:
            report = self._reports.get(report_id)
            if report is None:
                raise UnknownReportError(f"unknown report: {report_id!r}")
            return report

    def open_reports(self) -> List[AbuseReport]:
        with self._lock:
            return sorted(
                (r for r in self._reports.values() if r.state == "open"),
                key=lambda r: r.report_id,
            )

    def reports_by_subject(self, subject_id: str) -> List[AbuseReport]:
        with self._lock:
            return sorted(
                (r for r in self._reports.values()
                 if r.subject_id == subject_id),
                key=lambda r: r.report_id,
            )

    def report_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._reports)

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)


def abuse_reporter_audit_event(
    event: str, payload: Dict[str, Any]
) -> Dict[str, Any]:
    """Build an audit event envelope for the abuse reporter."""
    return {
        "event": event,
        "schema": SCHEMA_PIN,
        "module_version": ABUSE_REPORTER_VERSION,
        "payload": payload,
    }


def main() -> None:
    mgr = AbuseReporter(seed=b"abuse-reporter-selfcheck")
    rep = mgr.report("user-1", "user-9", "spam", "spammy posts", 1,
                     evidence=("https://example/x/1",))
    assert rep.report_id == "abr-1" and rep.state == "open"
    assert rep.verify(mgr)
    tri = mgr.triage("abr-1", "mod-1", 2, "high", "reviewer-2")
    assert tri.priority == "high" and tri.verify(mgr)
    assert mgr.get_report("abr-1").state == "triaged"
    res = mgr.resolve("abr-1", "reviewer-2", 3, "content-removed", "ok")
    assert res.action == "content-removed" and res.verify(mgr)
    assert mgr.get_report("abr-1").state == "resolved"
    kinds = [e["event"] for e in mgr.audit_log()]
    assert kinds == ["reported", "triaged", "resolved"], kinds
    print("abuse-reporter OK: report, triage, resolve, pins, audit")


if __name__ == "__main__":
    main()
