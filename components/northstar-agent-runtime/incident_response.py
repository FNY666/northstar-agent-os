"""Incident response operations (triage / contain / resolve bookkeeping, simulated).

Research note: in incident management the response *operations* are a
distinct layer from the incident *lifecycle* and from regulatory
*reporting*. PagerDuty/Opsgenie/VictorOps encode the lifecycle
(triggered -> acknowledged -> escalated -> resolved), and the
industry consensus (SRE Workbook, Atlassian Incident Handbook) treats
the response itself as a separate accountable timeline: *triage* (what
is broken, how bad is it), *containment* (what did we do to stop the
bleed), and *resolution* (what is the declared terminal state). This
module is that layer, deliberately distinct from the siblings:

* ``incident_manager.py`` -- the PagerDuty-shaped lifecycle
  (``create`` / ``ack`` / ``escalate`` / ``resolve``).
* ``incident_receipts.py`` -- EU-AI-Act-Art-73-shaped regulatory
  reporting receipts.

Public API:

* ``open_response(incident_id, seq, ...)`` -> frozen ``ResponseRecord``:
  attaches a response session to an incident id. The incident id is a
  label the host supplies; this module never verifies an outage.
* ``triage(incident_id, severity, seq, ...)`` -> frozen ``TriageRecord``
  (``trg-N`` ids): books one severity triage decision over the pinned
  vocabulary ``SEV1``/``SEV2``/``SEV3``/``SEV4``. Re-triage books a
  new record (history is kept, nothing is overwritten).
* ``contain(incident_id, action, seq, ...)`` -> frozen
  ``ContainmentRecord`` (``con-N`` ids): books one declared
  containment action over the pinned vocabulary ``isolate`` /
  ``rollback`` / ``failover`` / ``throttle`` / ``block-traffic`` /
  ``revoke-credentials``.
* ``resolve(incident_id, seq, outcome=..., ...)`` -> frozen
  ``ResolutionRecord``: terminal. The outcome is pinned
  (``resolved`` / ``mitigated`` / ``false-positive``) and booked as
  *data*; ``mitigated`` means the host claims the bleed stopped while
  the underlying fault may persist.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs (claim-then-burn: failed mutations consume
their seq and book ``incident-response.rejected``; rewinds raise bare
without consuming), no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json``
try/except fallback, ``sha256:`` digest pins, and ``audit.ndjson/1``
events.

Honest scope: the module books *declared* response operations. It
cannot page a real responder, cannot verify that containment actually
stopped the bleed, and cannot prove an outage ended. Raw incident
summaries and action details travel as digest pins only -- they never
enter records and never cross the audit boundary.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
INCIDENT_RESPONSE_VERSION = "incident-response.v1"

#: Schema pin carried by records and audit events.
INCIDENT_RESPONSE_SCHEMA = "northstar.incident-response.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_OPENED = "incident-response.opened"
KIND_TRIAGED = "incident-response.triaged"
KIND_CONTAINED = "incident-response.contained"
KIND_RESOLVED = "incident-response.resolved"
KIND_REJECTED = "incident-response.rejected"
_KINDS = frozenset(
    {KIND_OPENED, KIND_TRIAGED, KIND_CONTAINED, KIND_RESOLVED, KIND_REJECTED}
)

#: Pinned severity vocabulary (SEV1 critical -> SEV4 low).
SEVERITY_SEV1 = "SEV1"
SEVERITY_SEV2 = "SEV2"
SEVERITY_SEV3 = "SEV3"
SEVERITY_SEV4 = "SEV4"
_SEVERITIES = frozenset(
    {SEVERITY_SEV1, SEVERITY_SEV2, SEVERITY_SEV3, SEVERITY_SEV4}
)

#: Pinned containment-action vocabulary.
ACTION_ISOLATE = "isolate"
ACTION_ROLLBACK = "rollback"
ACTION_FAILOVER = "failover"
ACTION_THROTTLE = "throttle"
ACTION_BLOCK_TRAFFIC = "block-traffic"
ACTION_REVOKE_CREDENTIALS = "revoke-credentials"
_ACTIONS = frozenset(
    {
        ACTION_ISOLATE,
        ACTION_ROLLBACK,
        ACTION_FAILOVER,
        ACTION_THROTTLE,
        ACTION_BLOCK_TRAFFIC,
        ACTION_REVOKE_CREDENTIALS,
    }
)

#: Pinned resolution-outcome vocabulary.
OUTCOME_RESOLVED = "resolved"
OUTCOME_MITIGATED = "mitigated"
OUTCOME_FALSE_POSITIVE = "false-positive"
_OUTCOMES = frozenset({OUTCOME_RESOLVED, OUTCOME_MITIGATED, OUTCOME_FALSE_POSITIVE})

#: Raw-text keys that may never cross the audit boundary (digest pins only).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "title",
        "service",
        "summary",
        "rationale",
        "detail",
        "details",
        "description",
        "resolution",
        "payload",
        "value",
        "raw",
        "body",
        "text",
    }
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed: refuse, never guess)
# ---------------------------------------------------------------------------


class IncidentResponseError(Exception):
    """Base class for all incident-response errors."""


class BadIncidentError(IncidentResponseError):
    """Malformed incident id or metadata."""


class DuplicateIncidentError(IncidentResponseError):
    """A response session is already open for this incident id."""


class UnknownIncidentError(IncidentResponseError):
    """No response session is open for this incident id."""


class ResolvedIncidentError(IncidentResponseError):
    """The response session is terminal; no further mutations allowed."""


class BadSeverityError(IncidentResponseError):
    """Severity is not in the pinned vocabulary."""


class BadActionError(IncidentResponseError):
    """Containment action is not in the pinned vocabulary."""


class BadOutcomeError(IncidentResponseError):
    """Resolution outcome is not in the pinned vocabulary."""


class BadDigestError(IncidentResponseError):
    """A digest pin is malformed."""


class SeqOrderError(IncidentResponseError):
    """Caller seq is not a strictly increasing int."""


class AuditKindError(IncidentResponseError):
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
        raise BadIncidentError(f"{name} must be a str")
    stripped = value.strip()
    if not stripped or len(stripped) > max_len:
        raise BadIncidentError(f"{name} must be 1..{max_len} chars")
    if any(ch.isspace() for ch in stripped):
        raise BadIncidentError(f"{name} must not contain whitespace")
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
class ResponseRecord:
    incident_id: str
    service: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": INCIDENT_RESPONSE_SCHEMA,
            "version": INCIDENT_RESPONSE_VERSION,
            "incident_id": self.incident_id,
            "service": self.service,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.incident_id, self.service, self.seq), "response-open"
        )


@dataclass(frozen=True)
class TriageRecord:
    triage_id: str
    incident_id: str
    severity: str
    rationale_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": INCIDENT_RESPONSE_SCHEMA,
            "version": INCIDENT_RESPONSE_VERSION,
            "triage_id": self.triage_id,
            "incident_id": self.incident_id,
            "severity": self.severity,
            "rationale_digest": self.rationale_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.triage_id,
                self.incident_id,
                self.severity,
                self.rationale_digest,
                self.seq,
            ),
            "triage",
        )


@dataclass(frozen=True)
class ContainmentRecord:
    containment_id: str
    incident_id: str
    action: str
    detail_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": INCIDENT_RESPONSE_SCHEMA,
            "version": INCIDENT_RESPONSE_VERSION,
            "containment_id": self.containment_id,
            "incident_id": self.incident_id,
            "action": self.action,
            "detail_digest": self.detail_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.containment_id,
                self.incident_id,
                self.action,
                self.detail_digest,
                self.seq,
            ),
            "containment",
        )


@dataclass(frozen=True)
class ResolutionRecord:
    incident_id: str
    outcome: str
    resolution_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": INCIDENT_RESPONSE_SCHEMA,
            "version": INCIDENT_RESPONSE_VERSION,
            "incident_id": self.incident_id,
            "outcome": self.outcome,
            "resolution_digest": self.resolution_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.incident_id,
                self.outcome,
                self.resolution_digest,
                self.seq,
            ),
            "resolution",
        )


@dataclass(frozen=True)
class ResponseStatus:
    incident_id: str
    open: bool
    triage_count: int
    containment_count: int
    latest_severity: str
    resolved: bool
    outcome: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": INCIDENT_RESPONSE_SCHEMA,
            "version": INCIDENT_RESPONSE_VERSION,
            "incident_id": self.incident_id,
            "open": self.open,
            "triage_count": self.triage_count,
            "containment_count": self.containment_count,
            "latest_severity": self.latest_severity,
            "resolved": self.resolved,
            "outcome": self.outcome,
        }


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def incident_response_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for the incident-response ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(
                f"audit detail must not carry raw-text key {key!r}"
            )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# IncidentResponse: the response-operations ledger
# ---------------------------------------------------------------------------


class IncidentResponse:
    """Bookkeeping for incident *response* operations.

    Triaging, containment, and resolution are booked as declared,
    digest-pinned decisions against pinned vocabularies. The ledger is a
    deterministic single-host state machine: no wall-clock, frozen
    records, fail-closed errors, ``sha256:`` digest pins, and
    ``audit.ndjson/1`` events for every transition (and every refusal).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._responses: Dict[str, ResponseRecord] = {}
        self._triages: Dict[str, List[TriageRecord]] = {}
        self._containments: Dict[str, List[ContainmentRecord]] = {}
        self._resolutions: Dict[str, ResolutionRecord] = {}
        self._triage_counter = 0
        self._containment_counter = 0
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
            incident_response_audit_event(audit_kind, seq, **detail)
        )

    def _fail(self, seq: int, exc: IncidentResponseError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    def _require_open(self, incident_id: str) -> ResponseRecord:
        record = self._responses.get(incident_id)
        if record is None:
            raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
        return record

    def _require_unresolved(self, incident_id: str) -> None:
        if incident_id in self._resolutions:
            raise ResolvedIncidentError(
                f"incident {incident_id!r} is resolved; response is terminal"
            )

    # -- mutations --------------------------------------------------------
    def open_response(
        self,
        incident_id: str,
        seq: int,
        service: str = "",
        title_digest: str = "",
    ) -> ResponseRecord:
        """Attach a response session to an incident id."""
        with self._lock:
            seq = self._claim(seq)
            try:
                incident_id = _check_id(incident_id, "incident_id")
                if not isinstance(service, str) or isinstance(service, bool):
                    raise BadIncidentError("service must be a str")
                if len(service) > 128:
                    raise BadIncidentError("service must be <= 128 chars")
                title_digest = _check_digest(
                    title_digest, "title_digest", allow_empty=True
                )
                if incident_id in self._responses:
                    raise DuplicateIncidentError(
                        f"response already open for {incident_id!r}"
                    )
            except IncidentResponseError as exc:
                self._fail(seq, exc, incident_id=str(incident_id))
            record = ResponseRecord(
                incident_id=incident_id,
                service=service,
                seq=seq,
                digest=_digest_pin(
                    (incident_id, service, seq), "response-open"
                ),
            )
            self._responses[incident_id] = record
            self._triages[incident_id] = []
            self._containments[incident_id] = []
            self._emit(
                KIND_OPENED,
                seq,
                incident_id=incident_id,
                service_digest=_digest_pin((service,), "label")
                if service
                else "",
                title_digest=title_digest,
                record_digest=record.digest,
            )
            return record

    def triage(
        self,
        incident_id: str,
        severity: str,
        seq: int,
        rationale_digest: str = "",
    ) -> TriageRecord:
        """Book one severity triage decision. History is kept."""
        with self._lock:
            seq = self._claim(seq)
            try:
                self._require_open(incident_id)
                self._require_unresolved(incident_id)
                if severity not in _SEVERITIES:
                    raise BadSeverityError(
                        f"severity must be one of {sorted(_SEVERITIES)}"
                    )
                rationale_digest = _check_digest(
                    rationale_digest, "rationale_digest", allow_empty=True
                )
            except IncidentResponseError as exc:
                self._fail(seq, exc, incident_id=str(incident_id))
            self._triage_counter += 1
            triage_id = f"trg-{self._triage_counter}"
            record = TriageRecord(
                triage_id=triage_id,
                incident_id=incident_id,
                severity=severity,
                rationale_digest=rationale_digest,
                seq=seq,
                digest=_digest_pin(
                    (
                        triage_id,
                        incident_id,
                        severity,
                        rationale_digest,
                        seq,
                    ),
                    "triage",
                ),
            )
            self._triages[incident_id].append(record)
            self._emit(
                KIND_TRIAGED,
                seq,
                triage_id=triage_id,
                incident_id=incident_id,
                severity=severity,
                rationale_digest=rationale_digest,
                record_digest=record.digest,
            )
            return record

    def contain(
        self,
        incident_id: str,
        action: str,
        seq: int,
        detail_digest: str = "",
    ) -> ContainmentRecord:
        """Book one declared containment action."""
        with self._lock:
            seq = self._claim(seq)
            try:
                self._require_open(incident_id)
                self._require_unresolved(incident_id)
                if action not in _ACTIONS:
                    raise BadActionError(
                        f"action must be one of {sorted(_ACTIONS)}"
                    )
                detail_digest = _check_digest(
                    detail_digest, "detail_digest", allow_empty=True
                )
            except IncidentResponseError as exc:
                self._fail(seq, exc, incident_id=str(incident_id))
            self._containment_counter += 1
            containment_id = f"con-{self._containment_counter}"
            record = ContainmentRecord(
                containment_id=containment_id,
                incident_id=incident_id,
                action=action,
                detail_digest=detail_digest,
                seq=seq,
                digest=_digest_pin(
                    (
                        containment_id,
                        incident_id,
                        action,
                        detail_digest,
                        seq,
                    ),
                    "containment",
                ),
            )
            self._containments[incident_id].append(record)
            self._emit(
                KIND_CONTAINED,
                seq,
                containment_id=containment_id,
                incident_id=incident_id,
                action=action,
                detail_digest=detail_digest,
                record_digest=record.digest,
            )
            return record

    def resolve(
        self,
        incident_id: str,
        seq: int,
        outcome: str = OUTCOME_RESOLVED,
        resolution_digest: str = "",
    ) -> ResolutionRecord:
        """Declare the terminal resolution. Refuses re-resolution."""
        with self._lock:
            seq = self._claim(seq)
            try:
                self._require_open(incident_id)
                self._require_unresolved(incident_id)
                if outcome not in _OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(_OUTCOMES)}"
                    )
                resolution_digest = _check_digest(
                    resolution_digest, "resolution_digest", allow_empty=True
                )
            except IncidentResponseError as exc:
                self._fail(seq, exc, incident_id=str(incident_id))
            record = ResolutionRecord(
                incident_id=incident_id,
                outcome=outcome,
                resolution_digest=resolution_digest,
                seq=seq,
                digest=_digest_pin(
                    (incident_id, outcome, resolution_digest, seq),
                    "resolution",
                ),
            )
            self._resolutions[incident_id] = record
            self._emit(
                KIND_RESOLVED,
                seq,
                incident_id=incident_id,
                outcome=outcome,
                resolution_digest=resolution_digest,
                record_digest=record.digest,
            )
            return record

    # -- pure-read views --------------------------------------------------
    def _view_seq_ok(self, seq: Any) -> None:
        _check_seq(seq)

    def response_record(self, incident_id: str, seq: int) -> ResponseRecord:
        """Return the open-response record. Pure read."""
        self._view_seq_ok(seq)
        record = self._responses.get(incident_id)
        if record is None:
            raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
        return record

    def triage_history(self, incident_id: str, seq: int) -> Tuple[TriageRecord, ...]:
        """Return the triage records, oldest first. Pure read."""
        self._view_seq_ok(seq)
        history = self._triages.get(incident_id)
        if history is None:
            raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
        return tuple(history)

    def containment_actions(
        self, incident_id: str, seq: int
    ) -> Tuple[ContainmentRecord, ...]:
        """Return the containment actions, oldest first. Pure read."""
        self._view_seq_ok(seq)
        actions = self._containments.get(incident_id)
        if actions is None:
            raise UnknownIncidentError(f"unknown incident: {incident_id!r}")
        return tuple(actions)

    def resolution_record(self, incident_id: str, seq: int) -> ResolutionRecord:
        """Return the terminal resolution record. Pure read."""
        self._view_seq_ok(seq)
        record = self._resolutions.get(incident_id)
        if record is None:
            raise UnknownIncidentError(
                f"no resolution booked for {incident_id!r}"
            )
        return record

    def status(self, incident_id: str, seq: int) -> ResponseStatus:
        """Return a digest-free status snapshot. Pure read."""
        self._view_seq_ok(seq)
        record = self.response_record(incident_id, seq)
        history = self._triages[incident_id]
        resolved = incident_id in self._resolutions
        return ResponseStatus(
            incident_id=record.incident_id,
            open=True,
            triage_count=len(history),
            containment_count=len(self._containments[incident_id]),
            latest_severity=history[-1].severity if history else "",
            resolved=resolved,
            outcome=(
                self._resolutions[incident_id].outcome if resolved else ""
            ),
        )

    def incident_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted open-response incident ids. Pure read."""
        self._view_seq_ok(seq)
        return tuple(sorted(self._responses))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counters. Pure read."""
        self._view_seq_ok(seq)
        return {
            "schema": INCIDENT_RESPONSE_SCHEMA,
            "version": INCIDENT_RESPONSE_VERSION,
            "responses": len(self._responses),
            "triages": self._triage_counter,
            "containments": self._containment_counter,
            "resolutions": len(self._resolutions),
            "audit_events": len(self._audit_events),
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """The booked audit events. Pure read."""
        self._view_seq_ok(seq)
        return tuple(self._audit_events)


def main() -> None:
    ledger = IncidentResponse()
    ledger.open_response("INC-001", 1, service="payments")
    digest = "sha256:" + hashlib.sha256(b"summary").hexdigest()
    ledger.triage("INC-001", "SEV2", 2, rationale_digest=digest)
    ledger.contain("INC-001", "rollback", 3, detail_digest=digest)
    ledger.resolve("INC-001", 4, outcome="resolved", resolution_digest=digest)
    status = ledger.status("INC-001", 5)
    assert status.resolved and status.outcome == "resolved"
    assert ledger.stats(6)["responses"] == 1
    print(
        "incident-response OK: open, triage, contain, resolve, pins, audit"
    )


if __name__ == "__main__":
    main()
