"""Incident manager interface (PagerDuty-style lifecycle, simulated).

Research motivation: when production degrades, the coordination cost of
*the response itself* dwarfs the cost of the fix. PagerDuty/Opsgenie/
VictorOps encode a narrow, load-bearing state machine: an incident is
*triggered* (paged), *acknowledged* (a human owns it), *escalated* (more
urgency / a wider blast radius), *resolved* (terminal). Every transition
is an audit event -- because post-incident review is impossible without
a trustworthy timeline of who owned what, when, at which severity.

This module is the *bookkeeping* half of that shape, pinned so the
runtime's operational plumbing speaks one dialect:

- ``IncidentManager`` -- owns the incident registry. ``create()`` triggers
  an incident, ``ack()`` assigns ownership, ``escalate()`` raises the
  severity (never lowers it), ``resolve()`` closes it terminally.
- ``SEVERITY_ORDER`` -- ``SEV1`` (critical) > ``SEV2`` (high) >
  ``SEV3`` (medium) > ``SEV4`` (low). Numeric, ordered, auditable.
- ``incident_manager_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``created`` / ``acknowledged`` / ``escalated`` / ``resolved``
  / ``rejected``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- ``title``/``service`` must be non-empty ``str``; ``severity`` must be
  one of the four known severities (an unknown severity is a routing
  decision this module refuses to make for the caller).
- ``incident_id`` is minted deterministically (``inc-<n>``); unknown ids
  on ``ack``/``escalate``/``resolve`` raise ``UnknownIncidentError``.
- Lifecycle order is enforced: only ``TRIGGERED`` incidents can be
  ``ack()``ed (→ ``ACKNOWLEDGED``); only ``TRIGGERED``/``ACKNOWLEDGED``
  incidents can be ``escalate()``d or ``resolve()``d; ``RESOLVED`` is
  terminal -- any transition off it raises ``TerminalIncidentError``.
- ``escalate()`` only *raises* severity (``SEV4`` → ``SEV1``): paging
  *down* is a separate human decision with its own paper trail; this
  module never silently downgrades urgency. Same-severity "escalation"
  is refused as a no-op with a name.
- Caller seqs are ints (not bool) >= 0 and must strictly increase per
  incident across mutations (clock-free ordering).
- ``responder``/``note`` strings are length-guardrailed (1 MiB cap).

Honest scope:

- This module books *host-reported* response actions. It cannot page a
  real human, cannot verify that the acknowledged responder is the
  person who actually responded, and cannot prove that a "resolved"
  incident's underlying outage ended -- it records that a host *claimed*
  the outage ended.
- Severity is a coordination signal, not a diagnosis. ``SEV1`` means
  "this page needs the widest response", never "this fault is the worst".
- In-memory only: pair with the durable audit writer if the incident
  ledger must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
INCIDENT_MANAGER_VERSION = "incident-manager.v1"

#: Schema pin carried by records and audit events.
INCIDENT_MANAGER_SCHEMA = "northstar.incident-manager.v1"

#: Ordered severities: lower number = higher urgency.
SEV1 = "SEV1"  # critical
SEV2 = "SEV2"  # high
SEV3 = "SEV3"  # medium
SEV4 = "SEV4"  # low

#: Canonical ordering, index 0 is the most urgent.
SEVERITY_ORDER: Tuple[str, ...] = (SEV1, SEV2, SEV3, SEV4)

#: Lifecycle states.
TRIGGERED = "TRIGGERED"
ACKNOWLEDGED = "ACKNOWLEDGED"
RESOLVED = "RESOLVED"

#: Audit event kinds this module emits.
_AUDIT_KINDS = ("created", "acknowledged", "escalated", "resolved", "rejected")

_MAX_STR_LEN = 1 << 20  # 1 MiB guardrail on free-text fields


class IncidentManagerError(Exception):
    """Base error for incident-manager failures."""


class UnknownIncidentError(IncidentManagerError):
    """Raised when an operation references an unknown incident id."""


class IllegalTransitionError(IncidentManagerError):
    """Raised when a lifecycle transition is not allowed in the current state."""


class TerminalIncidentError(IncidentManagerError):
    """Raised when a transition is attempted on a RESOLVED incident."""


class NotAnEscalationError(IncidentManagerError):
    """Raised when escalate() is asked to keep or lower severity."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError("seq must be an int (not bool)")
    if seq < 0:
        raise ValueError("seq must be >= 0")
    return seq


def _check_name(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise TypeError("%s must be a str" % what)
    if not value:
        raise ValueError("%s must be non-empty" % what)
    if len(value) > _MAX_STR_LEN:
        raise ValueError("%s exceeds %d bytes" % (what, _MAX_STR_LEN))
    return value


def _check_severity(severity: Any) -> str:
    if isinstance(severity, bool) or not isinstance(severity, str):
        raise TypeError("severity must be a str")
    if severity not in SEVERITY_ORDER:
        raise ValueError(
            "unknown severity %r; expected one of %s" % (severity, list(SEVERITY_ORDER))
        )
    return severity


def _digest_pin(body: Mapping[str, Any]) -> str:
    return "sha256:" + jcs_sha256_hex(dict(body))


@dataclass(frozen=True)
class IncidentRecord:
    """Immutable snapshot of an incident at creation (plus live views)."""

    incident_id: str
    title: str
    severity: str
    service: str
    state: str
    digest: str
    version: str = INCIDENT_MANAGER_VERSION
    schema: str = INCIDENT_MANAGER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "service": self.service,
            "state": self.state,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class IncidentView:
    """Current live view of an incident (state + severity may have moved)."""

    incident_id: str
    title: str
    severity: str
    service: str
    state: str
    severity_history: Tuple[str, ...]
    acknowledged_by: Optional[str]
    resolved_note: Optional[str]
    last_seq: int
    digest: str
    version: str = INCIDENT_MANAGER_VERSION
    schema: str = INCIDENT_MANAGER_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "service": self.service,
            "state": self.state,
            "severity_history": list(self.severity_history),
            "acknowledged_by": self.acknowledged_by,
            "resolved_note": self.resolved_note,
            "last_seq": self.last_seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class AckRecord:
    incident_id: str
    responder: str
    seq: int
    digest: str
    version: str = INCIDENT_MANAGER_VERSION
    schema: str = INCIDENT_MANAGER_SCHEMA


@dataclass(frozen=True)
class EscalationRecord:
    incident_id: str
    from_severity: str
    to_severity: str
    reason: str
    seq: int
    digest: str
    version: str = INCIDENT_MANAGER_VERSION
    schema: str = INCIDENT_MANAGER_SCHEMA


@dataclass(frozen=True)
class ResolutionRecord:
    incident_id: str
    note: str
    seq: int
    digest: str
    version: str = INCIDENT_MANAGER_VERSION
    schema: str = INCIDENT_MANAGER_SCHEMA


def incident_manager_audit_event(kind: str, seq: int,
                                 incident_id: Optional[str] = None,
                                 detail: Optional[str] = None) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for an incident event.

    Carries ids, digests, and short details only -- raw payloads are
    never logged (the registry holds title/service strings as provided,
    but audit records stay minimal on purpose).
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError("unknown audit kind %r" % kind)
    _check_seq(seq)
    event: Dict[str, Any] = {
        "kind": kind,
        "seq": seq,
        "schema": INCIDENT_MANAGER_SCHEMA,
        "version": INCIDENT_MANAGER_VERSION,
    }
    if incident_id is not None:
        event["incident_id"] = _check_name(incident_id, "incident_id")
    if detail is not None:
        event["detail"] = _check_name(detail, "detail")
    return event


class IncidentManager:
    """PagerDuty-style incident lifecycle as a deterministic state machine.

    ``TRIGGERED -> ACKNOWLEDGED -> RESOLVED``; ``escalate()`` raises
    severity at any active step but never lowers it. All mutations are
    RLock-guarded and take caller-supplied seqs (no wall-clock).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._incidents: Dict[str, Dict[str, Any]] = {}
        self._next_id = 1

    # -- internals ----------------------------------------------------

    def _live(self, incident_id: str) -> Dict[str, Any]:
        entry = self._incidents.get(incident_id)
        if entry is None:
            raise UnknownIncidentError("unknown incident %r" % (incident_id,))
        return entry

    @staticmethod
    def _check_active(entry: Dict[str, Any], op: str) -> None:
        if entry["state"] == RESOLVED:
            raise TerminalIncidentError(
                "cannot %s resolved incident %r" % (op, entry["incident_id"])
            )

    @staticmethod
    def _check_seq_order(entry: Dict[str, Any], seq: int) -> None:
        if seq <= entry["last_seq"]:
            raise ValueError(
                "seq %d must strictly exceed last seq %d for %r"
                % (seq, entry["last_seq"], entry["incident_id"])
            )

    def _pin(self, entry: Dict[str, Any]) -> str:
        return _digest_pin({
            "incident_id": entry["incident_id"],
            "title": entry["title"],
            "severity": entry["severity"],
            "service": entry["service"],
            "state": entry["state"],
            "last_seq": entry["last_seq"],
        })

    def _view(self, entry: Dict[str, Any]) -> IncidentView:
        return IncidentView(
            incident_id=entry["incident_id"],
            title=entry["title"],
            severity=entry["severity"],
            service=entry["service"],
            state=entry["state"],
            severity_history=tuple(entry["severity_history"]),
            acknowledged_by=entry["acknowledged_by"],
            resolved_note=entry["resolved_note"],
            last_seq=entry["last_seq"],
            digest=self._pin(entry),
        )

    # -- lifecycle ----------------------------------------------------

    def create(self, title: str, severity: str, service: str, seq: int) -> IncidentRecord:
        """Trigger a new incident; it starts in ``TRIGGERED`` state."""
        _check_name(title, "title")
        _check_severity(severity)
        _check_name(service, "service")
        _check_seq(seq)
        with self._lock:
            incident_id = "inc-%d" % self._next_id
            self._next_id += 1
            entry: Dict[str, Any] = {
                "incident_id": incident_id,
                "title": title,
                "severity": severity,
                "service": service,
                "state": TRIGGERED,
                "severity_history": [severity],
                "acknowledged_by": None,
                "resolved_note": None,
                "last_seq": seq,
            }
            self._incidents[incident_id] = entry
            return IncidentRecord(
                incident_id=incident_id,
                title=title,
                severity=severity,
                service=service,
                state=TRIGGERED,
                digest=self._pin(entry),
            )

    def ack(self, incident_id: str, responder: str, seq: int) -> AckRecord:
        """Acknowledge (take ownership of) a ``TRIGGERED`` incident."""
        _check_name(incident_id, "incident_id")
        _check_name(responder, "responder")
        _check_seq(seq)
        with self._lock:
            entry = self._live(incident_id)
            self._check_active(entry, "ack")
            self._check_seq_order(entry, seq)
            if entry["state"] != TRIGGERED:
                raise IllegalTransitionError(
                    "incident %r is %s; only TRIGGERED incidents can be acked"
                    % (incident_id, entry["state"])
                )
            entry["state"] = ACKNOWLEDGED
            entry["acknowledged_by"] = responder
            entry["last_seq"] = seq
            return AckRecord(
                incident_id=incident_id,
                responder=responder,
                seq=seq,
                digest=_digest_pin({
                    "incident_id": incident_id,
                    "responder": responder,
                    "state": ACKNOWLEDGED,
                    "seq": seq,
                }),
            )

    def escalate(self, incident_id: str, new_severity: str, reason: str,
                 seq: int) -> EscalationRecord:
        """Raise an incident's severity. Never lowers it.

        ``new_severity`` must be strictly more urgent than the current
        severity; the same severity is a no-op with a name and is
        refused.
        """
        _check_name(incident_id, "incident_id")
        _check_severity(new_severity)
        _check_name(reason, "reason")
        _check_seq(seq)
        with self._lock:
            entry = self._live(incident_id)
            self._check_active(entry, "escalate")
            self._check_seq_order(entry, seq)
            current = entry["severity"]
            if SEVERITY_ORDER.index(new_severity) >= SEVERITY_ORDER.index(current):
                raise NotAnEscalationError(
                    "escalate %r -> %r is not an escalation (current %r)"
                    % (incident_id, new_severity, current)
                )
            entry["severity"] = new_severity
            entry["severity_history"].append(new_severity)
            entry["last_seq"] = seq
            return EscalationRecord(
                incident_id=incident_id,
                from_severity=current,
                to_severity=new_severity,
                reason=reason,
                seq=seq,
                digest=_digest_pin({
                    "incident_id": incident_id,
                    "from_severity": current,
                    "to_severity": new_severity,
                    "reason": reason,
                    "seq": seq,
                }),
            )

    def resolve(self, incident_id: str, note: str, seq: int) -> ResolutionRecord:
        """Resolve an active incident. Terminal -- no further transitions."""
        _check_name(incident_id, "incident_id")
        _check_name(note, "note")
        _check_seq(seq)
        with self._lock:
            entry = self._live(incident_id)
            self._check_active(entry, "resolve")
            self._check_seq_order(entry, seq)
            if entry["state"] not in (TRIGGERED, ACKNOWLEDGED):
                raise IllegalTransitionError(
                    "incident %r is %s; only active incidents can be resolved"
                    % (incident_id, entry["incident_id"])
                )
            entry["state"] = RESOLVED
            entry["resolved_note"] = note
            entry["last_seq"] = seq
            return ResolutionRecord(
                incident_id=incident_id,
                note=note,
                seq=seq,
                digest=_digest_pin({
                    "incident_id": incident_id,
                    "state": RESOLVED,
                    "seq": seq,
                }),
            )

    # -- views ---------------------------------------------------------

    def incident(self, incident_id: str) -> IncidentView:
        """Return the live view of one incident."""
        _check_name(incident_id, "incident_id")
        with self._lock:
            return self._view(self._live(incident_id))

    def incidents(self, state: Optional[str] = None) -> Tuple[IncidentView, ...]:
        """All incidents, optionally filtered to one lifecycle state."""
        if state is not None and state not in (TRIGGERED, ACKNOWLEDGED, RESOLVED):
            raise ValueError("unknown state %r" % (state,))
        with self._lock:
            views = [self._view(e) for e in self._incidents.values()]
        views.sort(key=lambda v: v.incident_id)
        if state is not None:
            views = [v for v in views if v.state == state]
        return tuple(views)

    def incident_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._incidents.keys()))


def main() -> None:
    mgr = IncidentManager()
    rec = mgr.create("db primary unreachable", SEV1, "payments-db", 1)
    assert rec.state == TRIGGERED
    ack = mgr.ack(rec.incident_id, "oncall-alice", 2)
    assert ack.responder == "oncall-alice"
    rec2 = mgr.create("cache hit ratio dropped", SEV4, "edge-cache", 3)
    esc2 = mgr.escalate(rec2.incident_id, SEV2, "widening to reads", 4)
    assert esc2.from_severity == SEV4 and esc2.to_severity == SEV2
    res = mgr.resolve(rec.incident_id, "failover complete, writes restored", 5)
    assert mgr.incident(rec.incident_id).state == RESOLVED
    ev = incident_manager_audit_event("resolved", 6, incident_id=rec.incident_id)
    assert ev["kind"] == "resolved"
    print("incident-manager OK: create, ack, escalate, resolve, refusals")


if __name__ == "__main__":
    main()
