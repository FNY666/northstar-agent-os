"""SIEM (security information and event management) decision ledger.

Ingest -> correlate -> alert lifecycle for security operations as a
deterministic single-host state machine (the shape this mirrors:
Splunk/Elastic-SIEM/Sentinel-style normalization + rule correlation +
alert routing, reduced to a *governance* ledger).

House style:
  - frozen dataclasses, caller int seqs strictly increasing (no wall-clock)
  - RLock-guarded, fail-closed, stdlib-only
  - `sha256:` digest pins with `verify()`
  - `audit.ndjson/1` events; raw event payloads stay out of the audit
    boundary (digest pins only)
  - failed mutations consume their seq (claim-then-burn) and book
    `siem.rejected`

Honest scope: books *declared* normalization decisions over
*host-reported* events, *declared* correlation outcomes, and *declared*
alert routings. A booked `match` means the host declared a rule fired -
never proof an attack happened. This module ingests no logs, runs no
correlation engine, watches no network and routes nothing; every event
is GIGO bookkeeping data.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # pragma: no cover - sibling convention
    from canonical_json import jcs_dumps  # type: ignore
except Exception:  # pragma: no cover
    def jcs_dumps(obj: Any) -> bytes:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

VERSION = "siem.v1"
SCHEMA = "northstar.siem.v1"

SOURCE_KINDS = (
    "syslog",
    "edr",
    "firewall",
    "ids",
    "cloud-audit",
    "auth-log",
    "dns",
)

EVENT_KINDS = (
    "auth-failure",
    "privilege-escalation",
    "malware-detected",
    "anomalous-egress",
    "lateral-movement",
    "config-change",
    "policy-violation",
    "port-scan",
    "data-access",
    "service-crash",
)

SEVERITIES = ("info", "low", "medium", "high", "critical")

RULES = (
    "impossible-travel",
    "brute-force",
    "exfiltration-pattern",
    "lateral-chain",
    "persistence-mechanism",
    "privilege-chain",
)

VERDICTS = ("match", "no-match", "inconclusive")

CHANNELS = ("siem", "email", "pagerduty", "slack", "ticket")

ALERT_SEVERITIES = ("low", "medium", "high", "critical")

_HASH_DOMAIN = b"northstar.siem.v1\x00"


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class SIEMError(Exception):
    """Base."""


class BadSourceError(SIEMError):
    pass


class DuplicateSourceError(SIEMError):
    pass


class UnknownSourceError(SIEMError):
    pass


class BadSourceKindError(SIEMError):
    pass


class BadEventError(SIEMError):
    pass


class UnknownEventError(SIEMError):
    pass


class BadEventKindError(SIEMError):
    pass


class BadSeverityError(SIEMError):
    pass


class BadRuleError(SIEMError):
    pass


class UnknownCorrelationError(SIEMError):
    pass


class BadVerdictError(SIEMError):
    pass


class BadChannelError(SIEMError):
    pass


class BadDigestError(SIEMError):
    pass


class SeqOrderError(SIEMError):
    pass


class AuditKindError(SIEMError):
    pass


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "source-registered",
    "event-ingested",
    "correlation-booked",
    "alert-raised",
    "rejected",
)


def siem_audit_event(
    kind: str, detail: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"bad audit kind: {kind!r}")
    _check_audit_detail(dict(detail or {}))
    return {
        "kind": kind,
        "detail": dict(detail or {}),
        "schema": "audit.ndjson/1",
    }


_BANNED_AUDIT_KEYS = (
    "payload",
    "raw",
    "event",
    "message",
    "text",
    "content",
    "log",
    "packet",
    "command",
    "password",
    "secret",
    "args",
    "stdout",
    "stderr",
)


def _check_audit_detail(detail: Dict[str, Any]) -> None:
    for key in _BANNED_AUDIT_KEYS:
        if key in detail:
            raise BadDigestError(f"raw data key banned from audit boundary: {key!r}")


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------

def _check_id(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BadSourceError(f"bad id: {value!r}")
    if len(value) > 128:
        raise BadSourceError("id too long")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"bad seq: {seq!r}")
    return seq


def _check_digest(value: Any) -> str:
    # raw event payloads never enter the ledger; pins only
    if not isinstance(value, str):
        raise BadDigestError(f"bad digest: {value!r}")
    if value == "":
        return value
    if len(value) != 7 + 64 or not value.startswith("sha256:"):
        raise BadDigestError(f"bad digest: {value!r}")
    try:
        int(value[7:], 16)
    except ValueError:
        raise BadDigestError(f"bad digest: {value!r}")
    return value


def _digest_pin(*parts: Any) -> str:
    blob = jcs_dumps([_HASH_DOMAIN.hex()] + list(parts))
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    source_kind: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(self.source_id, self.source_kind)


@dataclass(frozen=True)
class EventRecord:
    event_id: str
    source_id: str
    event_kind: str
    severity: str
    event_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.event_id,
            self.source_id,
            self.event_kind,
            self.severity,
            self.event_digest,
        )


@dataclass(frozen=True)
class CorrelationRecord:
    correlation_id: str
    rule: str
    event_ids: Tuple[str, ...]
    verdict: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.correlation_id,
            self.rule,
            list(self.event_ids),
            self.verdict,
        )


@dataclass(frozen=True)
class AlertRecord:
    alert_id: str
    correlation_id: str
    channel: str
    severity: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.alert_id,
            self.correlation_id,
            self.channel,
            self.severity,
        )


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------

class SIEM:
    """Ingest/correlate/alert decision ledger for security operations."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sources: Dict[str, SourceRecord] = {}
        self._events: Dict[str, EventRecord] = {}
        self._correlations: Dict[str, CorrelationRecord] = {}
        self._alerts: Dict[str, AlertRecord] = {}
        self._last_seq: int = -1
        self._event_seq = 0
        self._correlation_seq = 0
        self._alert_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline -----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq must strictly increase: {seq!r}")
        self._last_seq = seq
        return seq

    def _emit(self, audit_kind: str, detail: Dict[str, Any]) -> None:
        _check_audit_detail(detail)
        self._audit.append(siem_audit_event(audit_kind, detail))

    # -- sources ------------------------------------------------------------

    def register_source(
        self,
        source_id: Any,
        seq: Any,
        source_kind: Any = "syslog",
    ) -> SourceRecord:
        """Declare one log source feeding the SIEM."""
        with self._lock:
            seq = self._claim(seq)
            try:
                sid = _check_id(source_id)
                if sid in self._sources:
                    raise DuplicateSourceError(f"source exists: {sid!r}")
                if source_kind not in SOURCE_KINDS:
                    raise BadSourceKindError(f"bad source kind: {source_kind!r}")
                record = SourceRecord(
                    source_id=sid,
                    source_kind=source_kind,
                    digest=_digest_pin(sid, source_kind),
                )
                self._sources[sid] = record
                self._emit(
                    "source-registered",
                    {"source_id": sid, "source_kind": source_kind},
                )
                return record
            except SIEMError:
                self._emit("rejected", {"seq": seq, "op": "register_source"})
                raise

    def source_record(self, source_id: Any) -> SourceRecord:
        with self._lock:
            sid = _check_id(source_id)
            if sid not in self._sources:
                raise UnknownSourceError(f"unknown source: {sid!r}")
            return self._sources[sid]

    def source_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._sources))

    # -- ingest -------------------------------------------------------------

    def ingest(
        self,
        source_id: Any,
        event_kind: Any,
        seq: Any,
        event_digest: Any = "",
        severity: Any = "info",
    ) -> EventRecord:
        """Book one normalized event from a registered source.

        The raw event travels as a `sha256:` pin only - raw payloads
        never enter a record. The booked kind/severity are host-declared
        normalization decisions, booked as data.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                sid = _check_id(source_id)
                if sid not in self._sources:
                    raise UnknownSourceError(f"unknown source: {sid!r}")
                if event_kind not in EVENT_KINDS:
                    raise BadEventKindError(f"bad event kind: {event_kind!r}")
                if severity not in SEVERITIES:
                    raise BadSeverityError(f"bad severity: {severity!r}")
                e_digest = _check_digest(event_digest)
                self._event_seq += 1
                evt_id = f"evt-{self._event_seq}"
                record = EventRecord(
                    event_id=evt_id,
                    source_id=sid,
                    event_kind=event_kind,
                    severity=severity,
                    event_digest=e_digest,
                    digest=_digest_pin(
                        evt_id, sid, event_kind, severity, e_digest
                    ),
                )
                self._events[evt_id] = record
                self._emit(
                    "event-ingested",
                    {
                        "event_id": evt_id,
                        "source_id": sid,
                        "event_kind": event_kind,
                        "severity": severity,
                    },
                )
                return record
            except SIEMError:
                self._emit("rejected", {"seq": seq, "op": "ingest"})
                raise

    def event_record(self, event_id: Any) -> EventRecord:
        with self._lock:
            if not isinstance(event_id, str) or event_id not in self._events:
                raise UnknownEventError(f"unknown event: {event_id!r}")
            return self._events[event_id]

    def event_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._events))

    def events_for(self, source_id: Any) -> Tuple[str, ...]:
        with self._lock:
            sid = _check_id(source_id)
            if sid not in self._sources:
                raise UnknownSourceError(f"unknown source: {sid!r}")
            return tuple(
                sorted(
                    evt_id
                    for evt_id, rec in self._events.items()
                    if rec.source_id == sid
                )
            )

    # -- correlate ----------------------------------------------------------

    def correlate(
        self,
        rule: Any,
        event_ids: Any,
        seq: Any,
        verdict: Any = "no-match",
    ) -> CorrelationRecord:
        """Book one declared correlation of a rule over ingested events.

        All event ids must already be ingested; the verdict is booked
        **as data** - never proof a rule truly fired. `correlate()` runs
        no rule logic itself; it books the host's declared outcome.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                if rule not in RULES:
                    raise BadRuleError(f"bad rule: {rule!r}")
                if isinstance(event_ids, str) or not isinstance(
                    event_ids, (tuple, list)
                ):
                    raise BadEventError(f"bad event ids: {event_ids!r}")
                ids = tuple(event_ids)
                if not ids:
                    raise BadEventError("correlation needs at least one event")
                if len(set(ids)) != len(ids):
                    raise BadEventError("duplicate event ids in correlation")
                for evt_id in ids:
                    if not isinstance(evt_id, str) or evt_id not in self._events:
                        raise UnknownEventError(f"unknown event: {evt_id!r}")
                if verdict not in VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                self._correlation_seq += 1
                cor_id = f"cor-{self._correlation_seq}"
                record = CorrelationRecord(
                    correlation_id=cor_id,
                    rule=rule,
                    event_ids=ids,
                    verdict=verdict,
                    digest=_digest_pin(cor_id, rule, list(ids), verdict),
                )
                self._correlations[cor_id] = record
                self._emit(
                    "correlation-booked",
                    {
                        "correlation_id": cor_id,
                        "rule": rule,
                        "verdict": verdict,
                        "events": len(ids),
                    },
                )
                return record
            except SIEMError:
                self._emit("rejected", {"seq": seq, "op": "correlate"})
                raise

    def correlation_record(self, correlation_id: Any) -> CorrelationRecord:
        with self._lock:
            if (
                not isinstance(correlation_id, str)
                or correlation_id not in self._correlations
            ):
                raise UnknownCorrelationError(
                    f"unknown correlation: {correlation_id!r}"
                )
            return self._correlations[correlation_id]

    def correlation_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._correlations))

    # -- alert --------------------------------------------------------------

    def alert(
        self,
        correlation_id: Any,
        seq: Any,
        channel: Any,
        severity: Any,
    ) -> AlertRecord:
        """Book one alert routing decision for a booked correlation.

        Alerts are repeatable (an alert chain per correlation); this
        books the *routing decision*, never proof a message was sent.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                if (
                    not isinstance(correlation_id, str)
                    or correlation_id not in self._correlations
                ):
                    raise UnknownCorrelationError(
                        f"unknown correlation: {correlation_id!r}"
                    )
                if channel not in CHANNELS:
                    raise BadChannelError(f"bad channel: {channel!r}")
                if severity not in ALERT_SEVERITIES:
                    raise BadSeverityError(f"bad severity: {severity!r}")
                self._alert_seq += 1
                alr_id = f"alr-{self._alert_seq}"
                record = AlertRecord(
                    alert_id=alr_id,
                    correlation_id=correlation_id,
                    channel=channel,
                    severity=severity,
                    digest=_digest_pin(alr_id, correlation_id, channel, severity),
                )
                self._alerts[alr_id] = record
                self._emit(
                    "alert-raised",
                    {
                        "alert_id": alr_id,
                        "correlation_id": correlation_id,
                        "channel": channel,
                        "severity": severity,
                    },
                )
                return record
            except SIEMError:
                self._emit("rejected", {"seq": seq, "op": "alert"})
                raise

    def alert_record(self, alert_id: Any) -> AlertRecord:
        with self._lock:
            if not isinstance(alert_id, str) or alert_id not in self._alerts:
                raise SIEMError(f"unknown alert: {alert_id!r}")
            return self._alerts[alert_id]

    def alerts_for(self, correlation_id: Any) -> Tuple[str, ...]:
        with self._lock:
            if (
                not isinstance(correlation_id, str)
                or correlation_id not in self._correlations
            ):
                raise UnknownCorrelationError(
                    f"unknown correlation: {correlation_id!r}"
                )
            return tuple(
                sorted(
                    alr_id
                    for alr_id, rec in self._alerts.items()
                    if rec.correlation_id == correlation_id
                )
            )

    # -- views --------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "version": VERSION,
                "schema": SCHEMA,
                "sources": len(self._sources),
                "events": len(self._events),
                "correlations": len(self._correlations),
                "alerts": len(self._alerts),
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._audit]


def main() -> None:
    siem = SIEM()
    s = siem.register_source("fw-edge-01", 1, source_kind="firewall")
    assert s.verify()
    e1 = siem.ingest("fw-edge-01", "auth-failure", 2, severity="medium")
    assert e1.event_id == "evt-1" and e1.verify()
    e2 = siem.ingest("fw-edge-01", "port-scan", 3, severity="high")
    assert e2.verify()
    cor = siem.correlate("brute-force", ("evt-1", "evt-2"), 4, verdict="match")
    assert cor.verify()
    a = siem.alert("cor-1", 5, "pagerduty", "high")
    assert a.verify() and siem.alerts_for("cor-1") == ("alr-1",)
    print("siem OK: register, ingest, correlate, alert, pins")


if __name__ == "__main__":  # pragma: no cover
    main()
