"""AI incident reporting: serious-incident reporting ledger, Simulated.

Research note: serious-incident reporting regimes (EU AI Act Art. 73,
US EO 14110 Sec. 4.2(a), incident databases like AIID) structure the same
dangerous funnel: the organization must *report* an incident (what kind, how
severe), *track* it (status updates as the investigation unfolds), and
*close* it (resolved, mitigated, false-positive). The dangerous half of an
incident report is the *detail*: system internals, personal data, log excerpts,
and reproduction steps must never be bundled with the bookkeeping record
that tracks the reporting lifecycle itself.

This module is that bookkeeping layer, deliberately distinct from its
siblings ``incident_response.py`` (which owns the triage/contain/resolve
*response operations* ledger) and ``vuln_disclosure.py`` (which owns the
coordinated vulnerability *disclosure* lifecycle): this module books the
*reporting* lifecycle - report, track, close. It:

* **report()** - declare one AI incident (severity vocabulary, system and
  description digest pins only; raw details never enter a record).
* **track()** - book one declared status update (pinned statuses) as a
  repeatable tracking chain against a live incident.
* **close()** - terminal bookkeeping with a pinned outcome; ids never
  recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``incident-reporting.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked incident is a host-declared claim, never proof an
incident happened; a booked "under-investigation" is a declared status, never
proof of an investigation; a booked closure is the ledger's record of the
closure *decision*, never proof the incident was actually resolved.
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
INCIDENT_REPORTING_VERSION = "incident-reporting.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.incident-reporting.v1"

#: Pinned severity vocabulary (host-declared, never measured).
SEVERITIES = ("critical", "high", "medium", "low")

#: Pinned tracking-status vocabulary (declared, never proof of work done).
STATUSES = (
    "reported",
    "under-investigation",
    "mitigated",
    "resolved",
)

#: Pinned closure-outcome vocabulary.
CLOSE_OUTCOMES = ("resolved", "mitigated", "false-positive", "withdrawn")

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "reported",
    "tracked",
    "closed",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "incident",
        "description",
        "details",
        "detail",
        "system",
        "reporter",
        "report",
        "logs",
        "evidence",
        "payload",
        "secret",
        "raw",
        "text",
        "content",
        "data",
        "value",
        "input",
        "update",
        "notes",
        "note",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class IncidentReportingError(Exception):
    """Base error for incident-reporting ledger misuse."""


class BadIdError(IncidentReportingError):
    """Malformed incident / tracking / closure id."""


class DuplicateIncidentError(IncidentReportingError):
    """An incident id was declared twice."""


class RetiredIncidentError(IncidentReportingError):
    """An incident id was closed and can never be reused."""


class UnknownIncidentError(IncidentReportingError):
    """Reference to an incident id that was never declared."""


class BadDigestError(IncidentReportingError):
    """Malformed sha256: digest pin."""


class BadSeverityError(IncidentReportingError):
    """Severity outside the pinned vocabulary."""


class BadStatusError(IncidentReportingError):
    """Tracking status outside the pinned vocabulary."""


class BadOutcomeError(IncidentReportingError):
    """Closure outcome outside the pinned vocabulary."""


class TrackingStateError(IncidentReportingError):
    """Tracking attempted against an incident that is not open."""


class ClosureStateError(IncidentReportingError):
    """Closure refused: duplicate, or against a non-open incident."""


class SeqOrderError(IncidentReportingError):
    """Caller seq did not strictly increase."""


class AuditKindError(IncidentReportingError):
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


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IncidentRecord:
    """One declared AI incident (digest pins only, never details)."""

    incident_id: str
    system_digest: str
    severity: str
    reporter_digest: str
    description_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "incident_id": self.incident_id,
            "system_digest": self.system_digest,
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
                "incident_id": self.incident_id,
                "system_digest": self.system_digest,
                "severity": self.severity,
                "reporter_digest": self.reporter_digest,
                "description_digest": self.description_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class TrackingRecord:
    """One declared status update against an open incident."""

    tracking_id: str
    incident_id: str
    status: str
    update_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "tracking_id": self.tracking_id,
            "incident_id": self.incident_id,
            "status": self.status,
            "update_digest": self.update_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "tracking_id": self.tracking_id,
                "incident_id": self.incident_id,
                "status": self.status,
                "update_digest": self.update_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class ClosureRecord:
    """The terminal closure decision for a reported incident."""

    incident_id: str
    outcome: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "incident_id": self.incident_id,
            "outcome": self.outcome,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "incident_id": self.incident_id,
                "outcome": self.outcome,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class IncidentSummary:
    """Pure-read aggregation of one incident's reporting lifecycle."""

    incident_id: str
    severity: str
    status: str
    tracking_ids: Tuple[str, ...]
    closed: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "incident_id": self.incident_id,
            "severity": self.severity,
            "status": self.status,
            "tracking_ids": list(self.tracking_ids),
            "closed": self.closed,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "incident_id": self.incident_id,
                "severity": self.severity,
                "status": self.status,
                "tracking_ids": list(self.tracking_ids),
                "closed": self.closed,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def incident_reporting_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the incident-reporting ledger."""
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


class IncidentReporting:
    """AI incident reporting ledger (Simulated).

    ``report()`` / ``track()`` / ``close()`` mutate the ledger and consume
    caller seqs; ``summary()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._incidents: Dict[str, IncidentRecord] = {}
        self._status: Dict[str, str] = {}  # incident_id -> "open" | "closed"
        self._trackings: Dict[str, TrackingRecord] = {}
        self._incident_trackings: Dict[str, List[str]] = {}
        self._closures: Dict[str, ClosureRecord] = {}
        self._retired: set = set()
        self._trk_counter = 0
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
            row = incident_reporting_audit_event("rejected", seq,
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
        self._audit.append(incident_reporting_audit_event(audit_kind, seq, **details))

    # -- report ------------------------------------------------------------

    def report(
        self,
        incident_id: str,
        seq: int,
        system_digest: str = "",
        severity: str = "medium",
        reporter_digest: str = "",
        description_digest: str = "",
    ) -> IncidentRecord:
        """Book one AI incident report (digest pins only, never details)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(incident_id, "incident_id")
                if incident_id in self._retired:
                    raise RetiredIncidentError(
                        f"incident id retired forever: {incident_id!r}"
                    )
                if incident_id in self._incidents:
                    raise DuplicateIncidentError(
                        f"duplicate incident: {incident_id!r}"
                    )
                system_digest = _require_optional_digest(
                    system_digest, "system_digest"
                )
                reporter_digest = _require_optional_digest(
                    reporter_digest, "reporter_digest"
                )
                description_digest = _require_optional_digest(
                    description_digest, "description_digest"
                )
                if severity not in SEVERITIES:
                    raise BadSeverityError(f"bad severity: {severity!r}")
                record = IncidentRecord(
                    incident_id=incident_id,
                    system_digest=system_digest,
                    severity=severity,
                    reporter_digest=reporter_digest,
                    description_digest=description_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "incident_id": incident_id,
                            "system_digest": system_digest,
                            "severity": severity,
                            "reporter_digest": reporter_digest,
                            "description_digest": description_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._incidents[incident_id] = record
                self._status[incident_id] = "open"
                self._incident_trackings[incident_id] = []
                self._emit(
                    "reported",
                    seq,
                    incident_id=incident_id,
                    severity=severity,
                )
                return record
            except IncidentReportingError:
                self._burn(seq, "report", incident_id=incident_id)
                raise

    # -- track -------------------------------------------------------------

    def track(
        self,
        incident_id: str,
        seq: int,
        status: str,
        update_digest: str = "",
    ) -> TrackingRecord:
        """Book one declared status update against an open incident."""
        with self._lock:
            self._claim(seq)
            try:
                if not isinstance(incident_id, str) or not incident_id:
                    raise BadIdError("incident_id must be a non-empty str")
                if incident_id not in self._incidents:
                    raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
                if self._status[incident_id] != "open":
                    raise TrackingStateError(
                        f"incident is not open: {incident_id!r}"
                    )
                if status not in STATUSES:
                    raise BadStatusError(f"bad status: {status!r}")
                update_digest = _require_optional_digest(
                    update_digest, "update_digest"
                )
                self._trk_counter += 1
                tracking_id = f"trk-{self._trk_counter}"
                record = TrackingRecord(
                    tracking_id=tracking_id,
                    incident_id=incident_id,
                    status=status,
                    update_digest=update_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "tracking_id": tracking_id,
                            "incident_id": incident_id,
                            "status": status,
                            "update_digest": update_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._trackings[tracking_id] = record
                self._incident_trackings[incident_id].append(tracking_id)
                self._emit(
                    "tracked",
                    seq,
                    tracking_id=tracking_id,
                    incident_id=incident_id,
                    status=status,
                )
                return record
            except IncidentReportingError:
                self._burn(seq, "track", incident_id=incident_id)
                raise

    # -- close -------------------------------------------------------------

    def close(
        self,
        incident_id: str,
        seq: int,
        outcome: str = "resolved",
    ) -> ClosureRecord:
        """Terminally close a reported incident with a pinned outcome."""
        with self._lock:
            self._claim(seq)
            try:
                if not isinstance(incident_id, str) or not incident_id:
                    raise BadIdError("incident_id must be a non-empty str")
                if incident_id not in self._incidents:
                    raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
                if self._status[incident_id] != "open":
                    raise ClosureStateError(
                        f"incident is not open: {incident_id!r}"
                    )
                if outcome not in CLOSE_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                record = ClosureRecord(
                    incident_id=incident_id,
                    outcome=outcome,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "incident_id": incident_id,
                            "outcome": outcome,
                            "seq": seq,
                        }
                    ),
                )
                self._closures[incident_id] = record
                self._status[incident_id] = "closed"
                self._retired.add(incident_id)
                self._emit(
                    "closed",
                    seq,
                    incident_id=incident_id,
                    outcome=outcome,
                )
                return record
            except IncidentReportingError:
                self._burn(seq, "close", incident_id=incident_id)
                raise

    # -- pure-read views ----------------------------------------------------

    def incident_record(self, incident_id: str, seq: int) -> IncidentRecord:
        """Return one incident record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(incident_id, "incident_id")
            if incident_id not in self._incidents:
                raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
            return self._incidents[incident_id]

    def tracking_record(self, tracking_id: str, seq: int) -> TrackingRecord:
        """Return one tracking record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(tracking_id, "tracking_id")
            if tracking_id not in self._trackings:
                raise UnknownIncidentError(f"unknown tracking: {tracking_id!r}")
            return self._trackings[tracking_id]

    def closure_record(self, incident_id: str, seq: int) -> ClosureRecord:
        """Return one closure record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(incident_id, "incident_id")
            if incident_id not in self._closures:
                raise UnknownIncidentError(
                    f"incident was not closed: {incident_id!r}"
                )
            return self._closures[incident_id]

    def incident_ids(self, seq: int) -> Tuple[str, ...]:
        """All reported incident ids in reporting order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._incidents.keys())

    def tracking_ids_for(self, incident_id: str, seq: int) -> Tuple[str, ...]:
        """Tracking ids booked against one incident, in mint order."""
        with self._lock:
            self._check_seq(seq)
            _require_id(incident_id, "incident_id")
            if incident_id not in self._incidents:
                raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
            return tuple(self._incident_trackings[incident_id])

    def open_ids(self, seq: int) -> Tuple[str, ...]:
        """Ids of incidents that are still open (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(
                iid for iid, st in self._status.items() if st == "open"
            )

    def closed_ids(self, seq: int) -> Tuple[str, ...]:
        """Ids of incidents that are closed (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(
                iid for iid, st in self._status.items() if st == "closed"
            )

    def summary(self, incident_id: str, seq: int) -> IncidentSummary:
        """Pure-read aggregation of one incident's reporting lifecycle."""
        with self._lock:
            self._check_seq(seq)
            _require_id(incident_id, "incident_id")
            if incident_id not in self._incidents:
                raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
            rec = self._incidents[incident_id]
            closed = self._status[incident_id] == "closed"
            trackings = tuple(self._incident_trackings[incident_id])
            status = "closed" if closed else "open"
            summary = IncidentSummary(
                incident_id=incident_id,
                severity=rec.severity,
                status=status,
                tracking_ids=trackings,
                closed=closed,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "incident_id": incident_id,
                        "severity": rec.severity,
                        "status": status,
                        "tracking_ids": list(trackings),
                        "closed": closed,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return summary

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "incidents": len(self._incidents),
                "open": sum(1 for st in self._status.values() if st == "open"),
                "closed": sum(1 for st in self._status.values() if st == "closed"),
                "trackings": len(self._trackings),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the reporting ledger end to end."""
    ir = IncidentReporting()
    ir.report("inc-1", 1, severity="critical")
    ir.track("inc-1", 2, "under-investigation")
    ir.track("inc-1", 3, "mitigated")
    ir.close("inc-1", 4, outcome="mitigated")
    assert ir.incident_record("inc-1", 5).verify()
    assert ir.summary("inc-1", 6).closed is True
    assert ir.summary("inc-1", 7).tracking_ids == ("trk-1", "trk-2")
    assert ir.stats(8) == {"incidents": 1, "open": 0, "closed": 1, "trackings": 2}
    print("incident-reporting OK: report, track, close, summary, pins, audit")


if __name__ == "__main__":
    main()
