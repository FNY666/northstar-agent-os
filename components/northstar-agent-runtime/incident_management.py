"""Incident management: PagerDuty/Opsgenie-shaped incident lifecycle bookkeeping.

An ``IncidentManagement`` ledger books host-reported incident-lifecycle
decisions as a deterministic single-host state machine:

- ``register_policy(policy_id, levels, seq)`` pins an escalation policy:
  ordered levels, each a tuple of responder ids. Level ``n`` (1-based)
  owns ``levels[n-1]``.
- ``create(incident_id, title, severity, seq, ...)`` opens an incident in
  the ``triggered`` state. Severity is pinned to the PagerDuty vocabulary
  (``critical``/``error``/``warning``/``info``); urgency defaults from
  severity (``high`` for critical/error, ``low`` otherwise) unless the
  caller overrides it.
- ``acknowledge(incident_id, responder, seq)`` moves
  ``triggered`` -> ``acknowledged``. Double-acknowledge is refused
  fail-closed.
- ``escalate(incident_id, seq, reason="")`` bumps the escalation level and
  books the responders of the new level. A policy-attached incident caps
  at ``len(levels)`` (further escalation raises ``MaxEscalationError``);
  a policy-less incident escalates with an empty responder set.
- ``resolve(incident_id, seq, resolution="")`` is terminal. Mutations on a
  resolved incident raise ``ResolvedIncidentError`` fail-closed.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``incident-management.v1``, schema pin
``northstar.incident-management.v1``, ``main()`` self-check.

Honest scope: this module books *host-reported* incidents and cannot
detect real outages, cannot page real humans, cannot verify a responder
actually acted, and cannot prove an escalation notification was
delivered. Escalation here is a booked decision, never a delivered
notification. A quiet ledger means "no reported incidents", never "no
incidents".
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
INCIDENT_MANAGEMENT_VERSION = "incident-management.v1"

#: Schema pin carried by records and audit events.
INCIDENT_MANAGEMENT_SCHEMA = "northstar.incident-management.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned severity vocabulary (PagerDuty shape).
SEVERITIES = ("critical", "error", "warning", "info")

#: Pinned urgency vocabulary (PagerDuty shape).
URGENCIES = ("high", "low")

#: Pinned incident statuses.
STATUSES = ("triggered", "acknowledged", "resolved")

_STATUS_TRIGGERED = "triggered"
_STATUS_ACKNOWLEDGED = "acknowledged"
_STATUS_RESOLVED = "resolved"

_MAX_TITLE_LEN = 512
_MAX_RESPONDERS_PER_LEVEL = 64
_MAX_LEVELS = 32


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class IncidentManagementError(ValueError):
    """Base for all incident-management structural problems and refusals."""


class BadIncidentError(IncidentManagementError):
    """Incident id/title/severity/service/urgency is malformed."""


class DuplicateIncidentError(IncidentManagementError):
    """An incident id is already registered."""


class UnknownIncidentError(IncidentManagementError):
    """No incident is pinned for the requested id."""


class ResolvedIncidentError(IncidentManagementError):
    """The incident is resolved; the mutation is refused fail-closed."""


class BadPolicyError(IncidentManagementError):
    """Escalation policy id/levels are malformed."""


class DuplicatePolicyError(IncidentManagementError):
    """A policy id is already registered."""


class UnknownPolicyError(IncidentManagementError):
    """No policy is pinned for the requested id."""


class BadEscalationError(IncidentManagementError):
    """Escalation request is malformed (bad reason)."""


class MaxEscalationError(IncidentManagementError):
    """The incident is already at the policy's top escalation level."""


class BadAcknowledgeError(IncidentManagementError):
    """Acknowledge is malformed (bad responder) or the incident is not
    in the ``triggered`` state."""


class BadResolutionError(IncidentManagementError):
    """Resolution detail is malformed."""


class SeqOrderError(IncidentManagementError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IncidentManagementError(f"{name} must be a non-empty string")
    return value.strip()


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([INCIDENT_MANAGEMENT_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _default_urgency(severity: str) -> str:
    return "high" if severity in ("critical", "error") else "low"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyRecord:
    """One pinned escalation policy (frozen)."""

    policy_id: str
    levels: Tuple[Tuple[str, ...], ...]
    seq: int
    digest: str
    schema: str = INCIDENT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "policy", self.policy_id, [list(level) for level in self.levels],
            self.seq,
        )


@dataclass(frozen=True)
class IncidentRecord:
    """One pinned incident (frozen). ``status`` is lifecycle state."""

    incident_id: str
    title: str
    severity: str
    service: str
    urgency: str
    policy_id: str
    status: str
    escalation_level: int
    seq: int
    digest: str
    schema: str = INCIDENT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "incident", self.incident_id, self.title, self.severity,
            self.service, self.urgency, self.policy_id, self.seq,
        )


@dataclass(frozen=True)
class AckRecord:
    """One acknowledgement (frozen)."""

    incident_id: str
    responder: str
    seq: int
    digest: str
    schema: str = INCIDENT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "ack", self.incident_id, self.responder, self.seq
        )


@dataclass(frozen=True)
class EscalationRecord:
    """One escalation event (frozen). ``level`` is 1-based."""

    esc_id: str
    incident_id: str
    level: int
    responders: Tuple[str, ...]
    reason: str
    seq: int
    digest: str
    schema: str = INCIDENT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "escalate", self.esc_id, self.incident_id, self.level,
            list(self.responders), self.reason, self.seq,
        )


@dataclass(frozen=True)
class ResolutionRecord:
    """One terminal resolution (frozen)."""

    incident_id: str
    resolution: str
    seq: int
    digest: str
    schema: str = INCIDENT_MANAGEMENT_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "resolve", self.incident_id, self.resolution, self.seq
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_POLICY_REGISTERED = "incident.policy-registered"
KIND_CREATED = "incident.created"
KIND_ACKNOWLEDGED = "incident.acknowledged"
KIND_ESCALATED = "incident.escalated"
KIND_RESOLVED = "incident.resolved"
KIND_REJECTED = "incident.rejected"
_KINDS = (
    KIND_POLICY_REGISTERED, KIND_CREATED, KIND_ACKNOWLEDGED,
    KIND_ESCALATED, KIND_RESOLVED, KIND_REJECTED,
)


def incident_management_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the incident-management module."""
    if kind not in _KINDS:
        raise IncidentManagementError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise IncidentManagementError("detail must be a mapping")
    # Titles/resolutions may carry customer PII; pins only.
    banned = {"title", "resolution", "reason", "responders"}
    if any(k in detail for k in banned):
        raise IncidentManagementError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": INCIDENT_MANAGEMENT_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class IncidentManagement:
    """Deterministic incident-lifecycle ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._policies: Dict[str, PolicyRecord] = {}
        self._incidents: Dict[str, IncidentRecord] = {}
        self._escalations: Dict[str, List[EscalationRecord]] = {}
        self._esc_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _claim_seq(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _audit_locked(self, kind: str, detail: Mapping[str, Any]) -> None:
        self._audit.append(
            incident_management_audit_event(kind, detail, self._last_seq)
        )

    def _reject_locked(self, rejection: str) -> None:
        self._audit_locked(KIND_REJECTED, {"rejection": rejection})

    def _get_incident_locked(self, incident_id: str) -> IncidentRecord:
        record = self._incidents.get(incident_id)
        if record is None:
            self._reject_locked("unknown-incident")
            raise UnknownIncidentError(f"unknown incident {incident_id!r}")
        return record

    def _refuse_if_resolved_locked(self, record: IncidentRecord) -> None:
        if record.status == _STATUS_RESOLVED:
            self._reject_locked("resolved-incident")
            raise ResolvedIncidentError(
                f"incident {record.incident_id!r} is resolved"
            )

    # -- escalation policies --------------------------------------------

    def register_policy(
        self, policy_id: str, levels: Sequence[Sequence[str]], seq: int
    ) -> PolicyRecord:
        """Pin an escalation policy: ordered levels of responder ids."""
        with self._lock:
            policy_id = _check_nonempty_str(policy_id, "policy_id")
            if not isinstance(levels, Sequence) or isinstance(levels, (str, bytes)):
                raise BadPolicyError("levels must be a sequence of sequences")
            if not levels or len(levels) > _MAX_LEVELS:
                raise BadPolicyError(
                    f"levels must have 1..{_MAX_LEVELS} levels"
                )
            pinned: List[Tuple[str, ...]] = []
            for level in levels:
                if not isinstance(level, Sequence) or isinstance(level, (str, bytes)):
                    raise BadPolicyError("each level must be a sequence of responder ids")
                if not level or len(level) > _MAX_RESPONDERS_PER_LEVEL:
                    raise BadPolicyError(
                        "each level must have 1..%d responders"
                        % _MAX_RESPONDERS_PER_LEVEL
                    )
                responders = tuple(
                    _check_nonempty_str(r, "responder") for r in level
                )
                if len(set(responders)) != len(responders):
                    raise BadPolicyError("duplicate responder within a level")
                pinned.append(responders)
            levels_t = tuple(pinned)
            self._claim_seq(seq)
            if policy_id in self._policies:
                self._reject_locked("duplicate-policy")
                raise DuplicatePolicyError(
                    f"policy {policy_id!r} already registered"
                )
            record = PolicyRecord(
                policy_id=policy_id, levels=levels_t, seq=seq,
                digest=_pin(
                    "policy", policy_id,
                    [list(level) for level in levels_t], seq,
                ),
            )
            self._policies[policy_id] = record
            self._audit_locked(
                KIND_POLICY_REGISTERED,
                {"policy_id": policy_id, "digest": record.digest,
                 "levels": len(levels_t)},
            )
            return record

    # -- incidents ------------------------------------------------------

    def create(
        self,
        incident_id: str,
        title: str,
        severity: str,
        seq: int,
        *,
        service: str = "",
        urgency: Optional[str] = None,
        policy_id: str = "",
    ) -> IncidentRecord:
        """Open an incident in the ``triggered`` state."""
        with self._lock:
            incident_id = _check_nonempty_str(incident_id, "incident_id")
            title = _check_nonempty_str(title, "title")
            if len(title) > _MAX_TITLE_LEN:
                raise BadIncidentError(
                    f"title must be at most {_MAX_TITLE_LEN} chars"
                )
            if not isinstance(severity, str) or severity not in SEVERITIES:
                raise BadIncidentError(
                    f"severity must be one of {SEVERITIES}"
                )
            if not isinstance(service, str):
                raise BadIncidentError("service must be a string")
            service = service.strip()
            if urgency is None:
                urgency = _default_urgency(severity)
            if not isinstance(urgency, str) or urgency not in URGENCIES:
                raise BadIncidentError(f"urgency must be one of {URGENCIES}")
            if not isinstance(policy_id, str):
                raise BadIncidentError("policy_id must be a string")
            policy_id = policy_id.strip()
            if policy_id and policy_id not in self._policies:
                raise UnknownPolicyError(f"unknown policy {policy_id!r}")
            self._claim_seq(seq)
            if incident_id in self._incidents:
                self._reject_locked("duplicate-incident")
                raise DuplicateIncidentError(
                    f"incident {incident_id!r} already exists"
                )
            record = IncidentRecord(
                incident_id=incident_id, title=title, severity=severity,
                service=service, urgency=urgency, policy_id=policy_id,
                status=_STATUS_TRIGGERED, escalation_level=0, seq=seq,
                digest=_pin(
                    "incident", incident_id, title, severity, service,
                    urgency, policy_id, seq,
                ),
            )
            self._incidents[incident_id] = record
            self._escalations[incident_id] = []
            self._audit_locked(
                KIND_CREATED,
                {"incident_id": incident_id, "severity": severity,
                 "urgency": urgency, "digest": record.digest},
            )
            return record

    def acknowledge(
        self, incident_id: str, responder: str, seq: int
    ) -> AckRecord:
        """Move ``triggered`` -> ``acknowledged``."""
        with self._lock:
            incident_id = _check_nonempty_str(incident_id, "incident_id")
            responder = _check_nonempty_str(responder, "responder")
            self._claim_seq(seq)
            record = self._get_incident_locked(incident_id)
            self._refuse_if_resolved_locked(record)
            if record.status != _STATUS_TRIGGERED:
                self._reject_locked("already-acknowledged")
                raise BadAcknowledgeError(
                    f"incident {incident_id!r} is not triggered "
                    f"(status={record.status})"
                )
            updated = IncidentRecord(
                incident_id=record.incident_id, title=record.title,
                severity=record.severity, service=record.service,
                urgency=record.urgency, policy_id=record.policy_id,
                status=_STATUS_ACKNOWLEDGED,
                escalation_level=record.escalation_level, seq=record.seq,
                digest=record.digest,
            )
            self._incidents[incident_id] = updated
            ack = AckRecord(
                incident_id=incident_id, responder=responder, seq=seq,
                digest=_pin("ack", incident_id, responder, seq),
            )
            self._audit_locked(
                KIND_ACKNOWLEDGED,
                {"incident_id": incident_id, "digest": ack.digest},
            )
            return ack

    def escalate(
        self, incident_id: str, seq: int, reason: str = ""
    ) -> EscalationRecord:
        """Bump the escalation level and book the new level's responders."""
        with self._lock:
            incident_id = _check_nonempty_str(incident_id, "incident_id")
            if not isinstance(reason, str):
                raise BadEscalationError("reason must be a string")
            reason = reason.strip()
            self._claim_seq(seq)
            record = self._get_incident_locked(incident_id)
            self._refuse_if_resolved_locked(record)
            new_level = record.escalation_level + 1
            responders: Tuple[str, ...] = ()
            if record.policy_id:
                policy = self._policies[record.policy_id]
                if new_level > len(policy.levels):
                    self._reject_locked("max-escalation")
                    raise MaxEscalationError(
                        f"incident {incident_id!r} already at top level "
                        f"{len(policy.levels)}"
                    )
                responders = policy.levels[new_level - 1]
            self._esc_seq += 1
            esc_id = f"esc-{self._esc_seq}"
            escalation = EscalationRecord(
                esc_id=esc_id, incident_id=incident_id, level=new_level,
                responders=responders, reason=reason, seq=seq,
                digest=_pin(
                    "escalate", esc_id, incident_id, new_level,
                    list(responders), reason, seq,
                ),
            )
            updated = IncidentRecord(
                incident_id=record.incident_id, title=record.title,
                severity=record.severity, service=record.service,
                urgency=record.urgency, policy_id=record.policy_id,
                status=record.status, escalation_level=new_level,
                seq=record.seq, digest=record.digest,
            )
            self._incidents[incident_id] = updated
            self._escalations[incident_id].append(escalation)
            self._audit_locked(
                KIND_ESCALATED,
                {"incident_id": incident_id, "esc_id": esc_id,
                 "level": new_level, "digest": escalation.digest},
            )
            return escalation

    def resolve(
        self, incident_id: str, seq: int, resolution: str = ""
    ) -> ResolutionRecord:
        """Terminally resolve an incident."""
        with self._lock:
            incident_id = _check_nonempty_str(incident_id, "incident_id")
            if not isinstance(resolution, str):
                raise BadResolutionError("resolution must be a string")
            resolution = resolution.strip()
            self._claim_seq(seq)
            record = self._get_incident_locked(incident_id)
            self._refuse_if_resolved_locked(record)
            updated = IncidentRecord(
                incident_id=record.incident_id, title=record.title,
                severity=record.severity, service=record.service,
                urgency=record.urgency, policy_id=record.policy_id,
                status=_STATUS_RESOLVED,
                escalation_level=record.escalation_level, seq=record.seq,
                digest=record.digest,
            )
            self._incidents[incident_id] = updated
            result = ResolutionRecord(
                incident_id=incident_id, resolution=resolution, seq=seq,
                digest=_pin("resolve", incident_id, resolution, seq),
            )
            self._audit_locked(
                KIND_RESOLVED,
                {"incident_id": incident_id, "digest": result.digest},
            )
            return result

    # -- views ----------------------------------------------------------

    def incident(self, incident_id: str) -> IncidentRecord:
        """Return the pinned incident record (raises if unknown)."""
        with self._lock:
            record = self._incidents.get(incident_id)
            if record is None:
                raise UnknownIncidentError(
                    f"unknown incident {incident_id!r}"
                )
            return record

    def incident_ids(self) -> Tuple[str, ...]:
        """All incident ids, sorted."""
        with self._lock:
            return tuple(sorted(self._incidents))

    def open_ids(self) -> Tuple[str, ...]:
        """Incident ids whose status is not ``resolved``, sorted."""
        with self._lock:
            return tuple(
                sorted(
                    iid for iid, rec in self._incidents.items()
                    if rec.status != _STATUS_RESOLVED
                )
            )

    def policy(self, policy_id: str) -> PolicyRecord:
        """Return the pinned policy record (raises if unknown)."""
        with self._lock:
            record = self._policies.get(policy_id)
            if record is None:
                raise UnknownPolicyError(f"unknown policy {policy_id!r}")
            return record

    def policy_ids(self) -> Tuple[str, ...]:
        """All policy ids, sorted."""
        with self._lock:
            return tuple(sorted(self._policies))

    def escalations_for(self, incident_id: str) -> Tuple[EscalationRecord, ...]:
        """Escalation events for one incident, oldest first."""
        with self._lock:
            if incident_id not in self._incidents:
                raise UnknownIncidentError(
                    f"unknown incident {incident_id!r}"
                )
            return tuple(self._escalations[incident_id])

    def stats(self) -> Dict[str, int]:
        """Counts by status plus policy/escalation totals."""
        with self._lock:
            by_status = {s: 0 for s in STATUSES}
            for record in self._incidents.values():
                by_status[record.status] += 1
            return {
                "incidents": len(self._incidents),
                "triggered": by_status[_STATUS_TRIGGERED],
                "acknowledged": by_status[_STATUS_ACKNOWLEDGED],
                "resolved": by_status[_STATUS_RESOLVED],
                "policies": len(self._policies),
                "escalations": sum(len(v) for v in self._escalations.values()),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """The booked audit events, oldest first."""
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> Dict[str, Any]:
        """Summary view for debugging (no titles or resolutions)."""
        with self._lock:
            return {
                "schema": INCIDENT_MANAGEMENT_SCHEMA,
                "version": INCIDENT_MANAGEMENT_VERSION,
                "stats": self.stats(),
            }


def main() -> None:
    mgr = IncidentManagement()
    policy = mgr.register_policy("web-oncall", (("alice",), ("alice", "bob")), 1)
    assert policy.verify()
    inc = mgr.create("INC-1", "api 5xx spike", "critical", 2,
                     service="api", policy_id="web-oncall")
    assert inc.verify() and inc.status == "triggered"
    assert inc.urgency == "high"
    ack = mgr.acknowledge("INC-1", "alice", 3)
    assert ack.verify()
    esc1 = mgr.escalate("INC-1", 4, reason="no response")
    assert esc1.verify() and esc1.level == 1 and esc1.responders == ("alice",)
    esc2 = mgr.escalate("INC-1", 5)
    assert esc2.level == 2 and esc2.responders == ("alice", "bob")
    assert mgr.incident("INC-1").escalation_level == 2
    try:
        mgr.escalate("INC-1", 6)
    except MaxEscalationError:
        pass
    else:
        raise AssertionError("must refuse escalation past top level")
    res = mgr.resolve("INC-1", 7, resolution="rolled back deploy")
    assert res.verify()
    assert mgr.incident("INC-1").status == "resolved"
    assert mgr.open_ids() == ()
    try:
        mgr.acknowledge("INC-1", "alice", 8)
    except ResolvedIncidentError:
        pass
    else:
        raise AssertionError("must refuse mutation on resolved incident")
    print("incident-management OK: policy, create, ack, escalate, resolve")


if __name__ == "__main__":
    main()
