"""Vulnerability disclosure: coordinated vulnerability disclosure (CVD) ledger, Simulated.

Research note: coordinated vulnerability disclosure (ISO/IEC 29147) structures
the gap between discovery and public release - the reporter notifies the
vendor, both sides coordinate a fix timeline, and the advisory is published
only once remediation (or an embargo deadline) is declared. The dangerous
half of a disclosure is the *detail*: exploit code, proof-of-concept, and
affected-system identifiers must never be bundled with the bookkeeping
record that tracks the disclosure itself.

This module is that bookkeeping layer, deliberately distinct from its
sibling ``vuln_scanner.py`` (which owns detection mechanics): this module
runs no scanner, contacts no vendor, and leaks no exploit details. It books:

* **report()** - declare one vulnerability report (severity vocabulary,
  affected-system digest pin only; raw details never enter a record).
* **coordinate()** - book one coordination action (vendor-notified,
  fix-requested, timeline-set, embargo-extended, fix-verified) against a
  live report.
* **publish()** - book the advisory publication decision once at least one
  coordination action is on record; terminal for that report.
* **withdraw()** - terminal bookkeeping for false-positive / duplicate /
  out-of-scope reports, with a pinned reason.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``vuln-disclosure.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked report is a host-declared claim, never proof a
vulnerability exists; a booked "fix-verified" is a declared coordination
outcome, never proof the fix works; a booked publication is the ledger's
record of the publication *decision*, never proof the advisory was seen.
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
VULN_DISCLOSURE_VERSION = "vuln-disclosure.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.vuln-disclosure.v1"

#: Pinned severity vocabulary (host-declared, never measured).
SEVERITIES = ("critical", "high", "medium", "low", "informational")

#: Pinned coordination-action vocabulary (declared, never executed).
ACTIONS = (
    "vendor-notified",
    "fix-requested",
    "timeline-set",
    "embargo-extended",
    "fix-verified",
)

#: Pinned withdrawal-reason vocabulary.
WITHDRAW_REASONS = ("manual", "false-positive", "duplicate", "out-of-scope")

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "reported",
    "coordinated",
    "published",
    "withdrawn",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "exploit",
        "poc",
        "proof-of-concept",
        "payload",
        "vulnerability",
        "vuln",
        "crash",
        "stacktrace",
        "stack_trace",
        "secret",
        "raw",
        "text",
        "content",
        "data",
        "value",
        "input",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class VulnDisclosureError(Exception):
    """Base error for vuln-disclosure ledger misuse."""


class BadIdError(VulnDisclosureError):
    """Malformed report / coordination / publication id."""


class DuplicateReportError(VulnDisclosureError):
    """A report id was declared twice."""


class RetiredReportError(VulnDisclosureError):
    """A report id was withdrawn or published and can never be reused."""


class UnknownReportError(VulnDisclosureError):
    """Reference to a report id that was never declared."""


class BadDigestError(VulnDisclosureError):
    """Malformed sha256: digest pin."""


class BadSeverityError(VulnDisclosureError):
    """Severity outside the pinned vocabulary."""


class BadActionError(VulnDisclosureError):
    """Coordination action outside the pinned vocabulary."""


class BadReasonError(VulnDisclosureError):
    """Withdrawal reason outside the pinned vocabulary."""


class CoordinationStateError(VulnDisclosureError):
    """Coordination attempted against a report that is not live."""


class PublishStateError(VulnDisclosureError):
    """Publication refused: no coordination booked, duplicate, or not live."""


class SeqOrderError(VulnDisclosureError):
    """Caller seq did not strictly increase."""


class AuditKindError(VulnDisclosureError):
    """Unknown audit kind or banned raw key in an audit row."""


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_optional_digest(pin: str, field_name: str) -> str:
    if pin == "":
        return pin
    return _require_digest(pin, field_name)


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


@dataclass(frozen=True)
class ReportRecord:
    """One declared vulnerability report (digest pins only, never details)."""

    report_id: str
    affected_digest: str
    severity: str
    reporter_digest: str
    description_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "report_id": self.report_id,
            "affected_digest": self.affected_digest,
            "severity": self.severity,
            "reporter_digest": self.reporter_digest,
            "description_digest": self.description_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "report_id": self.report_id,
                "affected_digest": self.affected_digest,
                "severity": self.severity,
                "reporter_digest": self.reporter_digest,
                "description_digest": self.description_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class CoordinationRecord:
    """One declared coordination action against a live report."""

    coordination_id: str
    report_id: str
    action: str
    note_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "coordination_id": self.coordination_id,
            "report_id": self.report_id,
            "action": self.action,
            "note_digest": self.note_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "coordination_id": self.coordination_id,
                "report_id": self.report_id,
                "action": self.action,
                "note_digest": self.note_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class PublicationRecord:
    """The terminal publication decision for a coordinated report."""

    publication_id: str
    report_id: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "publication_id": self.publication_id,
            "report_id": self.report_id,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "publication_id": self.publication_id,
                "report_id": self.report_id,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class WithdrawRecord:
    """Terminal withdrawal of a report (pinned reason)."""

    report_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "report_id": self.report_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "report_id": self.report_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class DisclosureSummary:
    """Pure-read aggregation of one report's disclosure lifecycle."""

    report_id: str
    severity: str
    status: str
    coordination_ids: Tuple[str, ...]
    published: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "report_id": self.report_id,
            "severity": self.severity,
            "status": self.status,
            "coordination_ids": list(self.coordination_ids),
            "published": self.published,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "report_id": self.report_id,
                "severity": self.severity,
                "status": self.status,
                "coordination_ids": list(self.coordination_ids),
                "published": self.published,
            }
        )


def vuln_disclosure_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the vuln-disclosure ledger."""
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


class VulnDisclosure:
    """Coordinated vulnerability disclosure ledger (Simulated).

    ``report()`` / ``coordinate()`` / ``publish()`` / ``withdraw()`` mutate
    the ledger and consume caller seqs; ``summary()`` and all views are
    pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._reports: Dict[str, ReportRecord] = {}
        self._status: Dict[str, str] = {}  # report_id -> "open" | "published" | "withdrawn"
        self._coordinations: Dict[str, CoordinationRecord] = {}
        self._report_coordinations: Dict[str, List[str]] = {}
        self._publications: Dict[str, PublicationRecord] = {}
        self._withdrawals: Dict[str, WithdrawRecord] = {}
        self._retired: set = set()
        self._coord_counter = 0
        self._pub_counter = 0
        self._audit: List[Dict[str, Any]] = []

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
            row = vuln_disclosure_audit_event("rejected", seq,
                                             rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(vuln_disclosure_audit_event(audit_kind, seq, **details))

    # -- report ------------------------------------------------------------

    def report(
        self,
        report_id: str,
        seq: int,
        affected_digest: str = "",
        severity: str = "medium",
        reporter_digest: str = "",
        description_digest: str = "",
    ) -> ReportRecord:
        """Book one vulnerability report (digest pins only, never details)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(report_id, "report_id")
                if report_id in self._retired:
                    raise RetiredReportError(
                        f"report id retired forever: {report_id!r}"
                    )
                if report_id in self._reports:
                    raise DuplicateReportError(f"duplicate report: {report_id!r}")
                affected_digest = _require_optional_digest(
                    affected_digest, "affected_digest"
                )
                reporter_digest = _require_optional_digest(
                    reporter_digest, "reporter_digest"
                )
                description_digest = _require_optional_digest(
                    description_digest, "description_digest"
                )
                if severity not in SEVERITIES:
                    raise BadSeverityError(f"bad severity: {severity!r}")
                record = ReportRecord(
                    report_id=report_id,
                    affected_digest=affected_digest,
                    severity=severity,
                    reporter_digest=reporter_digest,
                    description_digest=description_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "report_id": report_id,
                            "affected_digest": affected_digest,
                            "severity": severity,
                            "reporter_digest": reporter_digest,
                            "description_digest": description_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._reports[report_id] = record
                self._status[report_id] = "open"
                self._report_coordinations[report_id] = []
                self._emit(
                    "reported",
                    seq,
                    report_id=report_id,
                    severity=severity,
                )
                return record
            except VulnDisclosureError:
                self._burn(seq, "report", report_id=report_id)
                raise

    # -- coordinate --------------------------------------------------------

    def coordinate(
        self,
        report_id: str,
        seq: int,
        action: str,
        note_digest: str = "",
    ) -> CoordinationRecord:
        """Book one coordination action against a live report."""
        with self._lock:
            self._claim(seq)
            try:
                if not isinstance(report_id, str) or not report_id:
                    raise BadIdError("report_id must be a non-empty str")
                if report_id not in self._reports:
                    raise UnknownReportError(f"unknown report: {report_id!r}")
                if self._status[report_id] != "open":
                    raise CoordinationStateError(
                        f"report is not live: {report_id!r}"
                    )
                if action not in ACTIONS:
                    raise BadActionError(f"bad action: {action!r}")
                note_digest = _require_optional_digest(note_digest, "note_digest")
                self._coord_counter += 1
                coordination_id = f"crd-{self._coord_counter}"
                record = CoordinationRecord(
                    coordination_id=coordination_id,
                    report_id=report_id,
                    action=action,
                    note_digest=note_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "coordination_id": coordination_id,
                            "report_id": report_id,
                            "action": action,
                            "note_digest": note_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._coordinations[coordination_id] = record
                self._report_coordinations[report_id].append(coordination_id)
                self._emit(
                    "coordinated",
                    seq,
                    coordination_id=coordination_id,
                    report_id=report_id,
                    action=action,
                )
                return record
            except VulnDisclosureError:
                self._burn(seq, "coordinate", report_id=report_id)
                raise

    # -- publish -----------------------------------------------------------

    def publish(self, report_id: str, seq: int) -> PublicationRecord:
        """Book the advisory publication decision (terminal for the report).

        Fail-closed: a publication requires at least one booked coordination
        action; the decision is a declared ledger event, never proof an
        advisory was seen.
        """
        with self._lock:
            self._claim(seq)
            try:
                if not isinstance(report_id, str) or not report_id:
                    raise BadIdError("report_id must be a non-empty str")
                if report_id not in self._reports:
                    raise UnknownReportError(f"unknown report: {report_id!r}")
                if self._status[report_id] != "open":
                    raise PublishStateError(
                        f"report is not live: {report_id!r}"
                    )
                if not self._report_coordinations.get(report_id):
                    raise PublishStateError(
                        f"no coordination booked for {report_id!r}"
                    )
                self._pub_counter += 1
                publication_id = f"pub-{self._pub_counter}"
                record = PublicationRecord(
                    publication_id=publication_id,
                    report_id=report_id,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "publication_id": publication_id,
                            "report_id": report_id,
                            "seq": seq,
                        }
                    ),
                )
                self._publications[publication_id] = record
                self._status[report_id] = "published"
                self._retired.add(report_id)
                self._emit(
                    "published",
                    seq,
                    publication_id=publication_id,
                    report_id=report_id,
                )
                return record
            except VulnDisclosureError:
                self._burn(seq, "publish", report_id=report_id)
                raise

    # -- withdraw ----------------------------------------------------------

    def withdraw(
        self, report_id: str, seq: int, reason: str = "manual"
    ) -> WithdrawRecord:
        """Terminally withdraw a report (pinned reason); ids never recycled."""
        with self._lock:
            self._claim(seq)
            try:
                if not isinstance(report_id, str) or not report_id:
                    raise BadIdError("report_id must be a non-empty str")
                if report_id in self._retired:
                    raise RetiredReportError(
                        f"report id retired forever: {report_id!r}"
                    )
                if report_id not in self._reports:
                    raise UnknownReportError(f"unknown report: {report_id!r}")
                if self._status[report_id] != "open":
                    raise CoordinationStateError(
                        f"report is not live: {report_id!r}"
                    )
                if reason not in WITHDRAW_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                record = WithdrawRecord(
                    report_id=report_id,
                    reason=reason,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "report_id": report_id,
                            "reason": reason,
                            "seq": seq,
                        }
                    ),
                )
                self._withdrawals[report_id] = record
                self._status[report_id] = "withdrawn"
                self._retired.add(report_id)
                self._emit(
                    "withdrawn",
                    seq,
                    report_id=report_id,
                    reason=reason,
                )
                return record
            except VulnDisclosureError:
                self._burn(seq, "withdraw", report_id=report_id)
                raise

    # -- pure-read views -----------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def report_record(self, report_id: str, seq: int) -> ReportRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._reports.get(report_id)
            if record is None:
                raise UnknownReportError(f"unknown report: {report_id!r}")
            return record

    def coordination_record(
        self, coordination_id: str, seq: int
    ) -> CoordinationRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._coordinations.get(coordination_id)
            if record is None:
                raise BadIdError(f"unknown coordination: {coordination_id!r}")
            return record

    def publication_record(self, report_id: str, seq: int) -> PublicationRecord:
        with self._lock:
            self._view_seq_ok(seq)
            for record in self._publications.values():
                if record.report_id == report_id:
                    return record
            raise UnknownReportError(f"no publication for {report_id!r}")

    def summary(self, report_id: str, seq: int) -> DisclosureSummary:
        """Pure read: one report's disclosure lifecycle as data."""
        with self._lock:
            self._view_seq_ok(seq)
            record = self._reports.get(report_id)
            if record is None:
                raise UnknownReportError(f"unknown report: {report_id!r}")
            coordination_ids = tuple(self._report_coordinations[report_id])
            status = self._status[report_id]
            pinned = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "report_id": report_id,
                    "severity": record.severity,
                    "status": status,
                    "coordination_ids": list(coordination_ids),
                    "published": status == "published",
                }
            )
            return DisclosureSummary(
                report_id=report_id,
                severity=record.severity,
                status=status,
                coordination_ids=coordination_ids,
                published=status == "published",
                digest=pinned,
            )

    def report_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._reports))

    def coordinations_for(self, report_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if report_id not in self._reports:
                raise UnknownReportError(f"unknown report: {report_id!r}")
            return tuple(self._report_coordinations[report_id])

    def published_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(
                sorted(
                    rid
                    for rid, status in self._status.items()
                    if status == "published"
                )
            )

    def withdrawn_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(
                sorted(
                    rid
                    for rid, status in self._status.items()
                    if status == "withdrawn"
                )
            )

    def is_published(self, report_id: str, seq: int) -> bool:
        with self._lock:
            self._view_seq_ok(seq)
            if report_id not in self._reports:
                raise UnknownReportError(f"unknown report: {report_id!r}")
            return self._status[report_id] == "published"

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "reports": len(self._reports),
                "open": sum(1 for s in self._status.values() if s == "open"),
                "published": sum(
                    1 for s in self._status.values() if s == "published"
                ),
                "withdrawn": sum(
                    1 for s in self._status.values() if s == "withdrawn"
                ),
                "coordinations": len(self._coordinations),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }


def main() -> None:
    vd = VulnDisclosure()
    rep = vd.report("VULN-1", 1, severity="critical")
    crd = vd.coordinate("VULN-1", 2, action="vendor-notified")
    pub = vd.publish("VULN-1", 3)
    wd = vd.report("VULN-2", 4, severity="low")
    vd.withdraw("VULN-2", 5, reason="false-positive")
    summary = vd.summary("VULN-1", 0)
    assert rep.verify() and crd.verify() and pub.verify()
    assert summary.verify() and summary.published
    assert vd.stats(0)["published"] == 1
    assert vd.stats(0)["withdrawn"] == 1
    print("vuln-disclosure OK: report, coordinate, publish, withdraw, pins, audit")


if __name__ == "__main__":
    main()
