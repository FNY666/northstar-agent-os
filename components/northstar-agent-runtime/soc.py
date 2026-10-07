"""SOC operations workflow ledger: book declared monitoring, escalation, tuning.

Distinct from siblings: ``soc_verdicts`` owns verdict cards and the
kill-switch mandate for autonomous remediation; ``incident_*`` owns the
incident lifecycle; ``alert_manager`` owns alerting. This module is the
*operations workflow* layer a security-operations center runs day to
day - it books declared monitoring scopes, declared event ingestions,
tiered escalations, and declared detector-sensitivity tunings as a
deterministic single-host state machine.

* **Monitors** - ``monitor()`` declares one SOC monitoring scope
  (``endpoint`` / ``network`` / ``identity`` / ``cloud`` /
  ``application`` / ``email``). Monitor ids are never recycled.
* **Events** - ``ingest()`` books one declared security event
  (caller-supplied ``event_id``) at the initial tier ``L1`` with a
  host-declared severity; the event content travels as a ``sha256:``
  digest pin only.
* **Escalations** - ``escalate()`` moves an event up exactly one tier
  (``L1`` -> ``L2`` -> ``L3`` -> ``incident``); same-tier, regressive,
  and tier-skipping escalations are refused fail-closed.
* **Tuning** - ``tune()`` books one declared sensitivity change for a
  monitor, recording the previous and new value; the rationale travels
  as a digest pin only.

Design (deterministic single-host ledger):
1. Frozen dataclasses, caller int seqs strictly increasing
   (claim-then-burn: failed mutations consume their seq + book
   ``soc.rejected``; rewinds raise bare), no wall-clock,
   RLock-guarded, fail-closed taxonomy.
2. stdlib-only + the single ``canonical_json`` try/except fallback;
   ``sha256:`` digest pins with ``verify()``; ``audit.ndjson/1``
   events; version pin ``soc.v1``; schema pin ``northstar.soc.v1``.

Honest scope:
- This module books *declared* SOC operations - it monitors nothing
  live, escalates nothing real, and tunes no actual detector.
- A booked event means "the host declared this event", never "the
  event happened". A booked escalation is a ledger decision, never
  proof a human was paged. A booked tuning is a declaration, never
  proof the detector changed.
- Digest pins prove ledger integrity and ordering, never the truth of
  the declared operations.
- No persistence: the ledger is in-memory.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


VERSION = "soc.v1"
SCHEMA = "northstar.soc.v1"

KIND_MONITOR_REGISTERED = "monitor-registered"
KIND_EVENT_INGESTED = "event-ingested"
KIND_ESCALATED = "escalated"
KIND_TUNED = "tuned"
KIND_REJECTED = "rejected"
_KINDS = frozenset({
    KIND_MONITOR_REGISTERED, KIND_EVENT_INGESTED, KIND_ESCALATED,
    KIND_TUNED, KIND_REJECTED,
})

_SCOPES = ("endpoint", "network", "identity", "cloud",
           "application", "email")

_SEVERITIES = ("low", "medium", "high", "critical")

_TIERS = ("L1", "L2", "L3", "incident")
_TIER_RANK = {tier: rank for rank, tier in enumerate(_TIERS)}

_SENSITIVITIES = ("low", "balanced", "high", "aggressive")

_REASONS = ("analyst-review", "severity-bump", "sla-breach",
            "playbook-match", "manual")

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Raw content must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset({
    "content", "text", "payload", "raw", "event_data", "rationale",
    "notes", "note", "description", "message", "source_ip", "hostname",
    "host", "user", "username", "evidence",
})


class SOCError(Exception):
    """Base class for all SOC ledger errors."""


class BadIdError(SOCError):
    """Malformed monitor id, event id, or escalation id."""


class DuplicateMonitorError(SOCError):
    """Monitor id already registered (ids are never recycled)."""


class UnknownMonitorError(SOCError):
    """Monitor id not registered."""


class BadScopeError(SOCError):
    """Scope not in the pinned vocabulary."""


class BadDigestError(SOCError):
    """Digest is not a sha256:<64hex> pin (or empty)."""


class BadSeverityError(SOCError):
    """Severity not in the pinned vocabulary."""


class DuplicateEventError(SOCError):
    """Event id already ingested (ids are never recycled)."""


class UnknownEventError(SOCError):
    """Event id not booked."""


class BadTierError(SOCError):
    """Escalation tier not in the pinned vocabulary."""


class TierOrderError(SOCError):
    """Escalation is not exactly one tier up (same, regressive, or skip)."""


class BadReasonError(SOCError):
    """Escalation reason not in the pinned vocabulary."""


class BadSensitivityError(SOCError):
    """Sensitivity not in the pinned vocabulary."""


class SameSensitivityError(SOCError):
    """Tuning to the sensitivity the monitor already has."""


class SeqOrderError(SOCError):
    """Malformed seq or seq not strictly increasing."""


class AuditKindError(SOCError):
    """Unknown audit kind, or banned key at the audit boundary."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str) -> str:
    """Validate a sha256:<64hex> digest pin (or empty string)."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{label} must be str, got {type(value).__name__}")
    if value and not _DIGEST_RE.match(value):
        raise BadDigestError(f"{label} must be sha256:<64hex> or empty")
    return value


def _digest_pin(payload: Any) -> str:
    """sha256: digest pin over canonical JSON of payload."""
    return "sha256:" + jcs_sha256_hex(payload)


def soc_audit_event(kind: str, detail: Dict[str, object],
                    seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the SOC ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "audit_version": "audit.ndjson/1",
        "schema": SCHEMA,
        "version": VERSION,
        "kind": "soc." + kind,
        "detail": dict(detail),
        "seq": seq,
    }


def _record_digest(tag: str, fields: Dict[str, object]) -> str:
    return _digest_pin({"soc": tag, **fields})


@dataclass(frozen=True)
class MonitorRecord:
    """One declared SOC monitoring scope."""

    monitor_id: str
    scope: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "monitor_id": self.monitor_id,
            "scope": self.scope,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest(
            "monitor", {"monitor_id": self.monitor_id, "scope": self.scope})


@dataclass(frozen=True)
class EventRecord:
    """One declared security event, booked at the initial tier L1.

    ``severity`` is host-declared bookkeeping data; ``event_pin`` pins
    the event content by digest only - the content itself never enters
    a record.
    """

    event_id: str
    monitor_id: str
    severity: str
    event_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "event_id": self.event_id,
            "monitor_id": self.monitor_id,
            "severity": self.severity,
            "tier": "L1",
            "event_pin": self.event_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("event", {
            "event_id": self.event_id, "monitor_id": self.monitor_id,
            "severity": self.severity, "event_pin": self.event_pin})


@dataclass(frozen=True)
class EscalationRecord:
    """One declared tier escalation for an event (minted esc-N).

    ``from_tier`` -> ``to_tier`` is always exactly one tier up; the
    escalation is a booked decision, never proof anyone was paged.
    """

    esc_id: str
    event_id: str
    from_tier: str
    to_tier: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "esc_id": self.esc_id,
            "event_id": self.event_id,
            "from_tier": self.from_tier,
            "to_tier": self.to_tier,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("escalation", {
            "esc_id": self.esc_id, "event_id": self.event_id,
            "from_tier": self.from_tier, "to_tier": self.to_tier,
            "reason": self.reason})


@dataclass(frozen=True)
class TuningRecord:
    """One declared sensitivity tuning for a monitor (minted tun-N).

    ``previous`` and ``sensitivity`` are the old and new pinned values;
    the rationale travels as a digest pin only.
    """

    tun_id: str
    monitor_id: str
    previous: str
    sensitivity: str
    rationale_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "tun_id": self.tun_id,
            "monitor_id": self.monitor_id,
            "previous": self.previous,
            "sensitivity": self.sensitivity,
            "rationale_pin": self.rationale_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("tuning", {
            "tun_id": self.tun_id, "monitor_id": self.monitor_id,
            "previous": self.previous, "sensitivity": self.sensitivity,
            "rationale_pin": self.rationale_pin})


class SOC:
    """SOC operations workflow ledger.

    Simulated: books host-declared monitors, event ingestions, tiered
    escalations, and sensitivity tunings. No live monitoring, no real
    escalation, no wall-clock, no randomness.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._monitors: Dict[str, MonitorRecord] = {}
        self._sensitivity: Dict[str, str] = {}
        self._events: Dict[str, EventRecord] = {}
        self._escalations: Dict[str, EscalationRecord] = {}
        self._tunings: Dict[str, TuningRecord] = {}
        self._esc_counter = 0
        self._tun_counter = 0
        self._audit_log: List[Dict[str, object]] = []
        self._rejected = 0

    def _claim_seq(self, seq: int) -> None:
        """Claim-then-burn: seq must be strictly increasing."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be > {self._seq}, got {seq}")

    def _emit(self, kind: str, detail: Dict[str, object],
              seq: int) -> None:
        self._audit_log.append(soc_audit_event(kind, detail, seq))

    def _burn(self, seq: int, what: str, exc: SOCError) -> None:
        self._seq = seq
        self._rejected += 1
        self._emit(KIND_REJECTED,
                   {"what": what, "why": type(exc).__name__}, seq)

    def monitor(self, monitor_id: object, scope: object,
                seq: object) -> MonitorRecord:
        """Declare one SOC monitoring scope; fail-closed on misuse."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _check_id(monitor_id, "monitor_id")
                if mid in self._monitors:
                    raise DuplicateMonitorError(
                        f"monitor already registered: {mid!r}")
                if not isinstance(scope, str) or scope not in _SCOPES:
                    raise BadScopeError(
                        f"scope must be one of {sorted(_SCOPES)}")
                rec = MonitorRecord(
                    monitor_id=mid, scope=scope,
                    digest=_record_digest(
                        "monitor", {"monitor_id": mid, "scope": scope}))
                self._monitors[mid] = rec
                self._sensitivity[mid] = "balanced"
                self._seq = seq_v
                self._emit(KIND_MONITOR_REGISTERED,
                           {"monitor_id": mid, "scope": scope}, seq_v)
                return rec
            except SOCError as exc:
                self._burn(seq_v, "monitor", exc)
                raise

    def ingest(self, monitor_id: object, event_id: object, seq: object,
               severity: object = "medium",
               event_digest: object = "") -> EventRecord:
        """Book one declared security event at the initial tier L1."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _check_id(monitor_id, "monitor_id")
                if mid not in self._monitors:
                    raise UnknownMonitorError(
                        f"unknown monitor: {mid!r}")
                eid = _check_id(event_id, "event_id")
                if eid in self._events:
                    raise DuplicateEventError(
                        f"event already ingested: {eid!r}")
                if not isinstance(severity, str) or severity not in _SEVERITIES:
                    raise BadSeverityError(
                        f"severity must be one of {sorted(_SEVERITIES)}")
                pin = _check_digest(event_digest, "event_digest")
                rec = EventRecord(
                    event_id=eid, monitor_id=mid, severity=severity,
                    event_pin=pin,
                    digest=_record_digest("event", {
                        "event_id": eid, "monitor_id": mid,
                        "severity": severity, "event_pin": pin}))
                self._events[eid] = rec
                self._seq = seq_v
                self._emit(KIND_EVENT_INGESTED,
                           {"event_id": eid, "monitor_id": mid,
                            "severity": severity, "tier": "L1"}, seq_v)
                return rec
            except SOCError as exc:
                self._burn(seq_v, "ingest", exc)
                raise

    def escalate(self, event_id: object, seq: object, to_tier: object,
                 reason: object = "analyst-review") -> EscalationRecord:
        """Move an event up exactly one tier; fail-closed otherwise."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                eid = _check_id(event_id, "event_id")
                if eid not in self._events:
                    raise UnknownEventError(f"unknown event: {eid!r}")
                if not isinstance(to_tier, str) or to_tier not in _TIERS:
                    raise BadTierError(
                        f"to_tier must be one of {sorted(_TIERS)}")
                if not isinstance(reason, str) or reason not in _REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(_REASONS)}")
                current = self.current_tier(eid, seq_v)
                if _TIER_RANK[to_tier] != _TIER_RANK[current] + 1:
                    raise TierOrderError(
                        f"escalation must move exactly one tier up "
                        f"from {current!r}, got {to_tier!r}")
                self._esc_counter += 1
                esc_id = f"esc-{self._esc_counter}"
                rec = EscalationRecord(
                    esc_id=esc_id, event_id=eid,
                    from_tier=current, to_tier=to_tier, reason=reason,
                    digest=_record_digest("escalation", {
                        "esc_id": esc_id, "event_id": eid,
                        "from_tier": current, "to_tier": to_tier,
                        "reason": reason}))
                self._escalations[esc_id] = rec
                self._seq = seq_v
                self._emit(KIND_ESCALATED,
                           {"esc_id": esc_id, "event_id": eid,
                            "from_tier": current, "to_tier": to_tier,
                            "reason": reason}, seq_v)
                return rec
            except SOCError as exc:
                self._burn(seq_v, "escalate", exc)
                raise

    def tune(self, monitor_id: object, seq: object, sensitivity: object,
             rationale_digest: object = "") -> TuningRecord:
        """Book one declared sensitivity change for a monitor."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _check_id(monitor_id, "monitor_id")
                if mid not in self._monitors:
                    raise UnknownMonitorError(
                        f"unknown monitor: {mid!r}")
                if (not isinstance(sensitivity, str)
                        or sensitivity not in _SENSITIVITIES):
                    raise BadSensitivityError(
                        f"sensitivity must be one of {sorted(_SENSITIVITIES)}")
                previous = self._sensitivity[mid]
                if sensitivity == previous:
                    raise SameSensitivityError(
                        f"monitor already at sensitivity {sensitivity!r}")
                pin = _check_digest(rationale_digest, "rationale_digest")
                self._tun_counter += 1
                tun_id = f"tun-{self._tun_counter}"
                rec = TuningRecord(
                    tun_id=tun_id, monitor_id=mid,
                    previous=previous, sensitivity=sensitivity,
                    rationale_pin=pin,
                    digest=_record_digest("tuning", {
                        "tun_id": tun_id, "monitor_id": mid,
                        "previous": previous, "sensitivity": sensitivity,
                        "rationale_pin": pin}))
                self._tunings[tun_id] = rec
                self._sensitivity[mid] = sensitivity
                self._seq = seq_v
                self._emit(KIND_TUNED,
                           {"tun_id": tun_id, "monitor_id": mid,
                            "previous": previous,
                            "sensitivity": sensitivity}, seq_v)
                return rec
            except SOCError as exc:
                self._burn(seq_v, "tune", exc)
                raise

    # ----- pure-read views (seq validated, never consumed, no audit rows) ---

    def monitor_record(self, monitor_id: object,
                       seq: object) -> MonitorRecord:
        """Pure read: fetch one monitor record (no seq consumption)."""
        with self._lock:
            _check_seq(seq)
            mid = _check_id(monitor_id, "monitor_id")
            if mid not in self._monitors:
                raise UnknownMonitorError(
                    f"unknown monitor: {mid!r}")
            return self._monitors[mid]

    def monitor_ids(self, seq: object) -> Tuple[str, ...]:
        """Pure read: all monitor ids in registration order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._monitors.keys())

    def sensitivity(self, monitor_id: object, seq: object) -> str:
        """Pure read: the monitor's current declared sensitivity."""
        with self._lock:
            _check_seq(seq)
            mid = _check_id(monitor_id, "monitor_id")
            if mid not in self._sensitivity:
                raise UnknownMonitorError(
                    f"unknown monitor: {mid!r}")
            return self._sensitivity[mid]

    def event_record(self, event_id: object,
                     seq: object) -> EventRecord:
        """Pure read: fetch one event record (no seq consumption)."""
        with self._lock:
            _check_seq(seq)
            eid = _check_id(event_id, "event_id")
            if eid not in self._events:
                raise UnknownEventError(f"unknown event: {eid!r}")
            return self._events[eid]

    def events_for(self, monitor_id: object,
                   seq: object) -> Tuple[str, ...]:
        """Pure read: event ids ingested under one monitor."""
        with self._lock:
            _check_seq(seq)
            mid = _check_id(monitor_id, "monitor_id")
            if mid not in self._monitors:
                raise UnknownMonitorError(
                    f"unknown monitor: {mid!r}")
            return tuple(e.event_id for e in self._events.values()
                         if e.monitor_id == mid)

    def current_tier(self, event_id: object, seq: object) -> str:
        """Pure read: the event's latest booked tier (L1 if untouched)."""
        with self._lock:
            _check_seq(seq)
            eid = _check_id(event_id, "event_id")
            if eid not in self._events:
                raise UnknownEventError(f"unknown event: {eid!r}")
            tier = "L1"
            for esc in self._escalations.values():
                if esc.event_id == eid:
                    tier = esc.to_tier
            return tier

    def escalations_for(self, event_id: object,
                        seq: object) -> Tuple[str, ...]:
        """Pure read: escalation ids booked for one event, in order."""
        with self._lock:
            _check_seq(seq)
            eid = _check_id(event_id, "event_id")
            if eid not in self._events:
                raise UnknownEventError(f"unknown event: {eid!r}")
            return tuple(e.esc_id for e in self._escalations.values()
                         if e.event_id == eid)

    def queue_for_tier(self, tier: object,
                       seq: object) -> Tuple[str, ...]:
        """Pure read: event ids whose current tier equals ``tier``."""
        with self._lock:
            _check_seq(seq)
            if not isinstance(tier, str) or tier not in _TIERS:
                raise BadTierError(
                    f"tier must be one of {sorted(_TIERS)}")
            out = []
            for eid in self._events:
                if self.current_tier(eid, seq) == tier:
                    out.append(eid)
            return tuple(out)

    def tunings_for(self, monitor_id: object,
                    seq: object) -> Tuple[str, ...]:
        """Pure read: tuning ids booked for one monitor, in order."""
        with self._lock:
            _check_seq(seq)
            mid = _check_id(monitor_id, "monitor_id")
            if mid not in self._monitors:
                raise UnknownMonitorError(
                    f"unknown monitor: {mid!r}")
            return tuple(t.tun_id for t in self._tunings.values()
                         if t.monitor_id == mid)

    def stats(self, seq: object) -> Dict[str, int]:
        """Pure read: ledger counts."""
        with self._lock:
            _check_seq(seq)
            return {
                "monitors": len(self._monitors),
                "events": len(self._events),
                "escalations": len(self._escalations),
                "tunings": len(self._tunings),
                "rejected": self._rejected,
                "seq": self._seq,
            }

    def audit_log(self, seq: object) -> Tuple[Dict[str, object], ...]:
        """Pure read: the audit rows booked so far."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit_log)


def main() -> None:
    """Self-check smoke: monitor, ingest, escalate, tune, pins, audit."""
    soc = SOC()
    mon = soc.monitor("m-endpoint", "endpoint", 1)
    assert mon.verify()
    evt = soc.ingest("m-endpoint", "evt-1", 2, severity="high",
                     event_digest="sha256:" + "b" * 64)
    assert evt.verify()
    assert soc.current_tier("evt-1", 3) == "L1"
    esc = soc.escalate("evt-1", 4, "L2", reason="severity-bump")
    assert esc.verify()
    assert soc.current_tier("evt-1", 5) == "L2"
    tun = soc.tune("m-endpoint", 6, "high",
                   rationale_digest="sha256:" + "c" * 64)
    assert tun.verify()
    assert soc.sensitivity("m-endpoint", 7) == "high"
    soc.stats(8)
    soc.audit_log(8)
    assert len(soc.audit_log(8)) == 4
    print("soc OK: monitor, ingest, escalate, tune, pins, audit")


if __name__ == "__main__":
    main()
