"""Crisis management bookkeeping (declare / coordinate / report / standdown).

Research note: crisis *management* is the governance layer above
incident *response*. ISO 22301 (business continuity), the NIST IR
lifecycle, and the corporate crisis literature (e.g. Coombs' SCCT)
all separate three things: the operational response to a fault
(what engineers do to the systems), the crisis declaration (who says
"this is a crisis", at what severity, and by what authority), and the
coordination work (executive notification, legal/PR/regulator
engagement, war-room activation, the terminal standdown decision).
This module is that governance layer, deliberately distinct from the
siblings:

* ``incident_response.py`` -- the incident *response operations*
  ledger (``triage`` / ``contain`` / ``resolve``): what was done to the
  systems. A crisis may wrap many incident responses; the ledger
  below never triages an incident itself.
* ``bcp.py`` -- business-continuity *plans* (``plan`` / ``test`` /
  ``activate``): the prepared playbook. This module books the
  declared decisions made *while* the plan (if any) is active.

Public API:

* ``declare(crisis_id, severity, seq, ...)`` -> frozen
  ``DeclarationRecord``: books one crisis declaration over the pinned
  severity vocabulary. Declared-by authority and the situation
  summary travel as digest pins only.
* ``coordinate(crisis_id, action, seq, ...)`` -> frozen
  ``CoordinationRecord`` (``crd-N`` ids): books one declared
  coordination decision over the pinned action vocabulary.
  Repeatable as a decision chain.
* ``report(crisis_id, seq, ...)`` -> frozen ``SituationReport``
  (``rep-N`` ids): books one declared situation report over the
  pinned status vocabulary.
* ``standdown(crisis_id, seq, ...)`` -> frozen ``StanddownRecord``:
  terminal. The outcome is pinned and booked as *data*; the id is
  retired forever.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs (claim-then-burn: failed mutations consume
their seq and book ``crisis-management.rejected``; rewinds raise bare
without consuming), no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json``
try/except fallback, ``sha256:`` digest pins, and ``audit.ndjson/1``
events.

Honest scope: the module books *declared* crisis decisions. It cannot
convene a war room, cannot page an executive, cannot verify a
situation summary, and cannot prove a crisis ended. Raw situation
text, names, and notes never enter records and never cross the audit
boundary -- digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
CRISIS_MANAGEMENT_VERSION = "crisis-management.v1"

#: Schema pin carried by records and audit events.
CRISIS_MANAGEMENT_SCHEMA = "northstar.crisis-management.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_DECLARED = "crisis-management.declared"
KIND_COORDINATED = "crisis-management.coordinated"
KIND_REPORTED = "crisis-management.reported"
KIND_STOOD_DOWN = "crisis-management.stood-down"
KIND_REJECTED = "crisis-management.rejected"
_KINDS = frozenset(
    {
        KIND_DECLARED,
        KIND_COORDINATED,
        KIND_REPORTED,
        KIND_STOOD_DOWN,
        KIND_REJECTED,
    }
)

#: Pinned crisis-severity vocabulary (catastrophic -> minor).
SEVERITY_CATASTROPHIC = "catastrophic"
SEVERITY_SEVERE = "severe"
SEVERITY_MAJOR = "major"
SEVERITY_MINOR = "minor"
_SEVERITIES = frozenset(
    {
        SEVERITY_CATASTROPHIC,
        SEVERITY_SEVERE,
        SEVERITY_MAJOR,
        SEVERITY_MINOR,
    }
)

#: Pinned coordination-action vocabulary (declared decisions, not actions).
ACTION_ACTIVATE_WAR_ROOM = "activate-war-room"
ACTION_NOTIFY_EXECUTIVES = "notify-executives"
ACTION_ENGAGE_LEGAL = "engage-legal"
ACTION_ENGAGE_PR = "engage-pr"
ACTION_ENGAGE_REGULATOR = "engage-regulator"
ACTION_FREEZE_CHANGES = "freeze-changes"
ACTION_FAILOVER_PRIMARY = "failover-primary"
ACTION_EVACUATE_SITE = "evacuate-site"
ACTION_RESTORE_SERVICE = "restore-service"
ACTION_ALL_CLEAR_COMMS = "all-clear-comms"
_ACTIONS = frozenset(
    {
        ACTION_ACTIVATE_WAR_ROOM,
        ACTION_NOTIFY_EXECUTIVES,
        ACTION_ENGAGE_LEGAL,
        ACTION_ENGAGE_PR,
        ACTION_ENGAGE_REGULATOR,
        ACTION_FREEZE_CHANGES,
        ACTION_FAILOVER_PRIMARY,
        ACTION_EVACUATE_SITE,
        ACTION_RESTORE_SERVICE,
        ACTION_ALL_CLEAR_COMMS,
    }
)

#: Pinned situation-report status vocabulary.
STATUS_ONGOING = "ongoing"
STATUS_STABILIZING = "stabilizing"
STATUS_CONTAINED = "contained"
STATUS_UNDER_REVIEW = "under-review"
_STATUSES = frozenset(
    {
        STATUS_ONGOING,
        STATUS_STABILIZING,
        STATUS_CONTAINED,
        STATUS_UNDER_REVIEW,
    }
)

#: Pinned standdown-outcome vocabulary.
OUTCOME_RESOLVED = "resolved"
OUTCOME_MITIGATED = "mitigated"
OUTCOME_FALSE_ALARM = "false-alarm"
OUTCOME_SUPERSEDED = "superseded"
_OUTCOMES = frozenset(
    {
        OUTCOME_RESOLVED,
        OUTCOME_MITIGATED,
        OUTCOME_FALSE_ALARM,
        OUTCOME_SUPERSEDED,
    }
)

#: Raw-text keys that may never cross the audit boundary (digest pins only).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "title",
        "situation",
        "note",
        "notes",
        "summary",
        "description",
        "detail",
        "details",
        "payload",
        "raw",
        "body",
        "text",
        "message",
        "objective",
        "rationale",
        "declared_by",
    }
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed: refuse, never guess)
# ---------------------------------------------------------------------------


class CrisisManagementError(Exception):
    """Base class for all crisis-management errors."""


class BadCrisisError(CrisisManagementError):
    """Malformed crisis id."""


class DuplicateCrisisError(CrisisManagementError):
    """A crisis is already declared for this id."""


class UnknownCrisisError(CrisisManagementError):
    """No crisis is declared for this id."""


class StoodDownCrisisError(CrisisManagementError):
    """The crisis is stood down; the id is retired forever."""


class BadSeverityError(CrisisManagementError):
    """Severity is not in the pinned vocabulary."""


class BadActionError(CrisisManagementError):
    """Coordination action is not in the pinned vocabulary."""


class BadStatusError(CrisisManagementError):
    """Situation-report status is not in the pinned vocabulary."""


class BadOutcomeError(CrisisManagementError):
    """Standdown outcome is not in the pinned vocabulary."""


class BadDigestError(CrisisManagementError):
    """A digest pin is malformed."""


class SeqOrderError(CrisisManagementError):
    """Caller seq is not a strictly increasing int."""


class AuditKindError(CrisisManagementError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Digest helpers (sha256: pins, type-tagged)
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    if _cj is not None:  # type: ignore[truthy-bool]
        data = _cj.jcs_dumps(obj)  # type: ignore[attr-defined]
        return data.encode("utf-8") if isinstance(data, str) else bytes(data)
    import json

    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest_pin(parts: Tuple[Any, ...], tag: str) -> str:
    return "sha256:" + hashlib.sha256(
        _canonical({"tag": tag, "parts": list(parts)})
    ).hexdigest()


def _check_digest(value: Any, name: str, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise BadDigestError(f"{name} must be a str")
    if value == "":
        if allow_empty:
            return ""
        raise BadDigestError(f"{name} must not be empty")
    if not value.startswith("sha256:") or len(value) != 7 + 64:
        raise BadDigestError(f"{name} must be a sha256:<64hex> pin")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{name} must be a sha256:<64hex> pin")
    return value


def _check_id(value: Any, name: str, max_len: int = 128) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise BadCrisisError(f"{name} must be a str")
    stripped = value.strip()
    if not stripped or len(stripped) > max_len:
        raise BadCrisisError(f"{name} must be 1..{max_len} chars")
    if any(ch.isspace() for ch in stripped):
        raise BadCrisisError(f"{name} must not contain whitespace")
    return stripped


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be >= 0")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen; digest-pinned)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeclarationRecord:
    crisis_id: str
    severity: str
    declared_by_digest: str
    situation_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": CRISIS_MANAGEMENT_SCHEMA,
            "version": CRISIS_MANAGEMENT_VERSION,
            "crisis_id": self.crisis_id,
            "severity": self.severity,
            "declared_by_digest": self.declared_by_digest,
            "situation_digest": self.situation_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.crisis_id,
                self.severity,
                self.declared_by_digest,
                self.situation_digest,
                self.seq,
            ),
            "crisis-declare",
        )


@dataclass(frozen=True)
class CoordinationRecord:
    coordination_id: str
    crisis_id: str
    action: str
    note_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": CRISIS_MANAGEMENT_SCHEMA,
            "version": CRISIS_MANAGEMENT_VERSION,
            "coordination_id": self.coordination_id,
            "crisis_id": self.crisis_id,
            "action": self.action,
            "note_digest": self.note_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.coordination_id,
                self.crisis_id,
                self.action,
                self.note_digest,
                self.seq,
            ),
            "crisis-coordinate",
        )


@dataclass(frozen=True)
class SituationReport:
    report_id: str
    crisis_id: str
    report_status: str
    situation_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": CRISIS_MANAGEMENT_SCHEMA,
            "version": CRISIS_MANAGEMENT_VERSION,
            "report_id": self.report_id,
            "crisis_id": self.crisis_id,
            "report_status": self.report_status,
            "situation_digest": self.situation_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.report_id,
                self.crisis_id,
                self.report_status,
                self.situation_digest,
                self.seq,
            ),
            "crisis-report",
        )


@dataclass(frozen=True)
class StanddownRecord:
    crisis_id: str
    outcome: str
    note_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": CRISIS_MANAGEMENT_SCHEMA,
            "version": CRISIS_MANAGEMENT_VERSION,
            "crisis_id": self.crisis_id,
            "outcome": self.outcome,
            "note_digest": self.note_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.crisis_id,
                self.outcome,
                self.note_digest,
                self.seq,
            ),
            "crisis-standdown",
        )


@dataclass(frozen=True)
class CrisisStatus:
    crisis_id: str
    declared: bool
    severity: str
    coordination_count: int
    report_count: int
    latest_status: str
    stood_down: bool
    outcome: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": CRISIS_MANAGEMENT_SCHEMA,
            "version": CRISIS_MANAGEMENT_VERSION,
            "crisis_id": self.crisis_id,
            "declared": self.declared,
            "severity": self.severity,
            "coordination_count": self.coordination_count,
            "report_count": self.report_count,
            "latest_status": self.latest_status,
            "stood_down": self.stood_down,
            "outcome": self.outcome,
        }


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def crisis_management_audit_event(
    audit_kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for the crisis-management ledger."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    _check_seq(seq)
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(
                f"audit detail must not carry raw-text key {key!r}"
            )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": audit_kind,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# CrisisManagement: the crisis-governance ledger
# ---------------------------------------------------------------------------


class CrisisManagement:
    """Bookkeeping for crisis *governance* decisions.

    Declaration, coordination decisions, situation reports, and the
    terminal standdown are booked as declared, digest-pinned decisions
    against pinned vocabularies. The ledger is a deterministic
    single-host state machine: no wall-clock, frozen records,
    fail-closed errors, ``sha256:`` digest pins, and ``audit.ndjson/1``
    events for every transition (and every refusal).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._declarations: Dict[str, DeclarationRecord] = {}
        self._coordinations: Dict[str, List[CoordinationRecord]] = {}
        self._reports: Dict[str, List[SituationReport]] = {}
        self._standdowns: Dict[str, StanddownRecord] = {}
        self._coordination_counter = 0
        self._report_counter = 0
        self._audit_events: List[Dict[str, Any]] = []

    # -- internals --------------------------------------------------------
    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} not strictly greater than {self._seq}"
            )
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(
            crisis_management_audit_event(audit_kind, seq, **detail)
        )

    def _fail(self, seq: int, exc: CrisisManagementError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    def _require_declared(self, crisis_id: str) -> DeclarationRecord:
        record = self._declarations.get(crisis_id)
        if record is None:
            raise UnknownCrisisError(f"unknown crisis: {crisis_id!r}")
        return record

    def _require_live(self, crisis_id: str) -> None:
        self._require_declared(crisis_id)
        if crisis_id in self._standdowns:
            raise StoodDownCrisisError(
                f"crisis {crisis_id!r} is stood down; id is retired"
            )

    # -- mutations --------------------------------------------------------
    def declare(
        self,
        crisis_id: str,
        severity: str,
        seq: int,
        declared_by_digest: str = "",
        situation_digest: str = "",
    ) -> DeclarationRecord:
        """Book one crisis declaration. Ids are never recycled."""
        with self._lock:
            seq = self._claim(seq)
            try:
                crisis_id = _check_id(crisis_id, "crisis_id")
                if severity not in _SEVERITIES:
                    raise BadSeverityError(
                        f"severity must be one of {sorted(_SEVERITIES)}"
                    )
                declared_by_digest = _check_digest(
                    declared_by_digest, "declared_by_digest", allow_empty=True
                )
                situation_digest = _check_digest(
                    situation_digest, "situation_digest", allow_empty=True
                )
                if crisis_id in self._standdowns:
                    raise StoodDownCrisisError(
                        f"crisis {crisis_id!r} is stood down; id is retired"
                    )
                if crisis_id in self._declarations:
                    raise DuplicateCrisisError(
                        f"crisis already declared for {crisis_id!r}"
                    )
            except CrisisManagementError as exc:
                self._fail(seq, exc, crisis_id=str(crisis_id))
            record = DeclarationRecord(
                crisis_id=crisis_id,
                severity=severity,
                declared_by_digest=declared_by_digest,
                situation_digest=situation_digest,
                seq=seq,
                digest=_digest_pin(
                    (
                        crisis_id,
                        severity,
                        declared_by_digest,
                        situation_digest,
                        seq,
                    ),
                    "crisis-declare",
                ),
            )
            self._declarations[crisis_id] = record
            self._coordinations[crisis_id] = []
            self._reports[crisis_id] = []
            self._emit(
                KIND_DECLARED,
                seq,
                crisis_id=crisis_id,
                severity=severity,
                declared_by_digest=declared_by_digest,
                situation_digest=situation_digest,
                record_digest=record.digest,
            )
            return record

    def coordinate(
        self,
        crisis_id: str,
        action: str,
        seq: int,
        note_digest: str = "",
    ) -> CoordinationRecord:
        """Book one declared coordination decision. Repeatable."""
        with self._lock:
            seq = self._claim(seq)
            try:
                self._require_live(crisis_id)
                if action not in _ACTIONS:
                    raise BadActionError(
                        f"action must be one of {sorted(_ACTIONS)}"
                    )
                note_digest = _check_digest(
                    note_digest, "note_digest", allow_empty=True
                )
            except CrisisManagementError as exc:
                self._fail(seq, exc, crisis_id=str(crisis_id))
            self._coordination_counter += 1
            coordination_id = f"crd-{self._coordination_counter}"
            record = CoordinationRecord(
                coordination_id=coordination_id,
                crisis_id=crisis_id,
                action=action,
                note_digest=note_digest,
                seq=seq,
                digest=_digest_pin(
                    (
                        coordination_id,
                        crisis_id,
                        action,
                        note_digest,
                        seq,
                    ),
                    "crisis-coordinate",
                ),
            )
            self._coordinations[crisis_id].append(record)
            self._emit(
                KIND_COORDINATED,
                seq,
                coordination_id=coordination_id,
                crisis_id=crisis_id,
                action=action,
                note_digest=note_digest,
                record_digest=record.digest,
            )
            return record

    def report(
        self,
        crisis_id: str,
        seq: int,
        report_status: str = STATUS_ONGOING,
        situation_digest: str = "",
    ) -> SituationReport:
        """Book one declared situation report. Repeatable."""
        with self._lock:
            seq = self._claim(seq)
            try:
                self._require_live(crisis_id)
                if report_status not in _STATUSES:
                    raise BadStatusError(
                        f"report_status must be one of {sorted(_STATUSES)}"
                    )
                situation_digest = _check_digest(
                    situation_digest, "situation_digest", allow_empty=True
                )
            except CrisisManagementError as exc:
                self._fail(seq, exc, crisis_id=str(crisis_id))
            self._report_counter += 1
            report_id = f"rep-{self._report_counter}"
            record = SituationReport(
                report_id=report_id,
                crisis_id=crisis_id,
                report_status=report_status,
                situation_digest=situation_digest,
                seq=seq,
                digest=_digest_pin(
                    (
                        report_id,
                        crisis_id,
                        report_status,
                        situation_digest,
                        seq,
                    ),
                    "crisis-report",
                ),
            )
            self._reports[crisis_id].append(record)
            self._emit(
                KIND_REPORTED,
                seq,
                report_id=report_id,
                crisis_id=crisis_id,
                report_status=report_status,
                situation_digest=situation_digest,
                record_digest=record.digest,
            )
            return record

    def standdown(
        self,
        crisis_id: str,
        seq: int,
        outcome: str = OUTCOME_RESOLVED,
        note_digest: str = "",
    ) -> StanddownRecord:
        """Declare the terminal standdown. The id is retired forever."""
        with self._lock:
            seq = self._claim(seq)
            try:
                self._require_live(crisis_id)
                if outcome not in _OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(_OUTCOMES)}"
                    )
                note_digest = _check_digest(
                    note_digest, "note_digest", allow_empty=True
                )
            except CrisisManagementError as exc:
                self._fail(seq, exc, crisis_id=str(crisis_id))
            record = StanddownRecord(
                crisis_id=crisis_id,
                outcome=outcome,
                note_digest=note_digest,
                seq=seq,
                digest=_digest_pin(
                    (crisis_id, outcome, note_digest, seq),
                    "crisis-standdown",
                ),
            )
            self._standdowns[crisis_id] = record
            self._emit(
                KIND_STOOD_DOWN,
                seq,
                crisis_id=crisis_id,
                outcome=outcome,
                note_digest=note_digest,
                record_digest=record.digest,
            )
            return record

    # -- pure-read views --------------------------------------------------
    def _view_seq_ok(self, seq: Any) -> None:
        _check_seq(seq)

    def declaration_record(
        self, crisis_id: str, seq: int
    ) -> DeclarationRecord:
        """Return the declaration record. Pure read."""
        self._view_seq_ok(seq)
        return self._require_declared(crisis_id)

    def coordination_history(
        self, crisis_id: str, seq: int
    ) -> Tuple[CoordinationRecord, ...]:
        """Return the coordination decisions, oldest first. Pure read."""
        self._view_seq_ok(seq)
        history = self._coordinations.get(crisis_id)
        if history is None:
            raise UnknownCrisisError(f"unknown crisis: {crisis_id!r}")
        return tuple(history)

    def situation_reports(
        self, crisis_id: str, seq: int
    ) -> Tuple[SituationReport, ...]:
        """Return the situation reports, oldest first. Pure read."""
        self._view_seq_ok(seq)
        reports = self._reports.get(crisis_id)
        if reports is None:
            raise UnknownCrisisError(f"unknown crisis: {crisis_id!r}")
        return tuple(reports)

    def standdown_record(self, crisis_id: str, seq: int) -> StanddownRecord:
        """Return the terminal standdown record. Pure read."""
        self._view_seq_ok(seq)
        record = self._standdowns.get(crisis_id)
        if record is None:
            raise UnknownCrisisError(
                f"no standdown booked for {crisis_id!r}"
            )
        return record

    def status(self, crisis_id: str, seq: int) -> CrisisStatus:
        """Return a status snapshot. Pure read."""
        self._view_seq_ok(seq)
        record = self.declaration_record(crisis_id, seq)
        reports = self._reports[crisis_id]
        stood_down = crisis_id in self._standdowns
        return CrisisStatus(
            crisis_id=record.crisis_id,
            declared=True,
            severity=record.severity,
            coordination_count=len(self._coordinations[crisis_id]),
            report_count=len(reports),
            latest_status=reports[-1].report_status if reports else "",
            stood_down=stood_down,
            outcome=(
                self._standdowns[crisis_id].outcome if stood_down else ""
            ),
        )

    def crisis_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted declared crisis ids. Pure read."""
        self._view_seq_ok(seq)
        return tuple(sorted(self._declarations))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counters. Pure read."""
        self._view_seq_ok(seq)
        return {
            "schema": CRISIS_MANAGEMENT_SCHEMA,
            "version": CRISIS_MANAGEMENT_VERSION,
            "declarations": len(self._declarations),
            "coordinations": self._coordination_counter,
            "reports": self._report_counter,
            "standdowns": len(self._standdowns),
            "audit_events": len(self._audit_events),
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """The booked audit events. Pure read."""
        self._view_seq_ok(seq)
        return tuple(self._audit_events)


def main() -> None:
    ledger = CrisisManagement()
    by = "sha256:" + hashlib.sha256(b"cto").hexdigest()
    sit = "sha256:" + hashlib.sha256(b"region outage").hexdigest()
    ledger.declare(
        "CR-001",
        "severe",
        1,
        declared_by_digest=by,
        situation_digest=sit,
    )
    ledger.coordinate("CR-001", "activate-war-room", 2, note_digest=by)
    ledger.report("CR-001", 3, report_status="ongoing", situation_digest=sit)
    ledger.standdown("CR-001", 4, outcome="resolved", note_digest=by)
    status = ledger.status("CR-001", 5)
    assert status.stood_down and status.outcome == "resolved"
    assert status.coordination_count == 1 and status.report_count == 1
    assert ledger.stats(6)["declarations"] == 1
    print(
        "crisis-management OK: declare, coordinate, report, standdown, "
        "pins, audit"
    )


if __name__ == "__main__":
    main()
