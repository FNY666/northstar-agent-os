"""Alert manager interface (Prometheus Alertmanager-style routing, simulated).

Research motivation: observability pipelines drown in raw alert events.
Prometheus Alertmanager (and its kin -- PagerDuty routing, Opsgenie
policies, Grafana OnCall) solve this with three bookkeeping primitives:

- *deduplication*: the same (name, labels) firing twice is one alert,
  not two pages at 3am;
- *silencing*: a known-bad window (a deploy, a maintenance) suppresses
  *routing* of matching alerts without deleting them -- the alert is
  still recorded, still auditable, just not paged;
- *routing*: ordered match rules pick a receiver (team-a-pager,
  team-b-slack); unmatched alerts fall through to a default receiver
  rather than vanishing.

This module is the *bookkeeping* half of that shape, pinned so the
runtime's observability plumbing speaks one dialect:

- ``AlertManager`` -- owns the alert registry, silence registry, and
  ordered routing rules. ``fire()`` admits an alert (idempotent on
  (name, labels) while active), ``resolve()`` closes one,
  ``silence()`` opens a suppression window, ``expire_silence()``
  closes it early, ``add_route_rule()`` appends a routing rule,
  ``route()`` computes the routing decision for every active alert.
- ``alert_manager_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``fired`` / ``resolved`` / ``silenced`` /
  ``silence-expired`` / ``route-rule-added`` / ``routed`` /
  ``rejected``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- ``name`` must be a non-empty ``str``; ``labels`` a mapping of
  non-empty ``str`` -> ``str``; ``severity`` one of
  ``critical`` / ``warning`` / ``info``; caller seqs are ints
  (not bool) >= 0.
- Firing an already-*active* alert with the same (name, labels) is
  idempotent and returns the existing record (Alertmanager dedup);
  re-firing after ``resolve()`` mints a *new* alert id.
- ``resolve()`` on an unknown id raises ``UnknownAlertError``; on an
  already-resolved alert raises ``AlreadyResolvedError`` -- a
  resolved alert never silently flips back to active.
- A silence must name at least one label matcher: empty ``matchers``
  are refused (no match-all silences -- silencing *everything* is a
  footgun, make it impossible by construction). The silence window
  must satisfy ``starts_seq <= ends_seq``.
- Routing never drops an alert: unmatched alerts go to the default
  receiver ``default-receiver``. A silenced alert is still reported
  in the route report with ``silenced=True`` and the matching
  ``silence_id`` -- suppression is visible, never invisible.

Honest scope:

- This module books *host-reported* alert events. It cannot verify
  that the condition it names is really happening, nor that a paged
  receiver actually got the page. A host that lies about labels gets
  a lying routing ledger.
- Silence windows are caller-supplied seq ranges, not wall-clock --
  the host owns "now". A silence whose window has lapsed is simply
  not matched; ``expire_silence()`` closes one early.
- In-memory only: pair with the durable audit writer if alert
  history must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

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
ALERT_MANAGER_VERSION = "alert-manager.v1"

#: Schema pin carried by records and audit events.
ALERT_MANAGER_SCHEMA = "northstar.alert-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Allowed severities.
CRITICAL = "critical"
WARNING = "warning"
INFO = "info"
_SEVERITIES = (CRITICAL, WARNING, INFO)

#: Alert lifecycle states.
ACTIVE = "active"
RESOLVED = "resolved"

#: Receiver used when no route rule matches.
DEFAULT_RECEIVER = "default-receiver"

#: Audit event kinds.
KIND_FIRED = "fired"
KIND_RESOLVED = "resolved"
KIND_SILENCED = "silenced"
KIND_SILENCE_EXPIRED = "silence-expired"
KIND_ROUTE_RULE_ADDED = "route-rule-added"
KIND_ROUTED = "routed"
_KINDS = (
    KIND_FIRED,
    KIND_RESOLVED,
    KIND_SILENCED,
    KIND_SILENCE_EXPIRED,
    KIND_ROUTE_RULE_ADDED,
    KIND_ROUTED,
)


class AlertManagerError(Exception):
    """Base error for the alert manager."""


class UnknownAlertError(AlertManagerError):
    """Alert id is not known to the registry."""


class AlreadyResolvedError(AlertManagerError):
    """Alert is already resolved; resolve() again is refused."""


class UnknownSilenceError(AlertManagerError):
    """Silence id is not known to the registry."""


class ExpiredSilenceError(AlertManagerError):
    """Silence is already expired."""


class DuplicateRuleError(AlertManagerError):
    """A rule with this id already exists (should not happen)."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise AlertManagerError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise AlertManagerError(f"{what} must be a non-empty str")
    return value


def _check_str_map(value: Any, what: str) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(value, Mapping):
        raise AlertManagerError(f"{what} must be a mapping of str -> str")
    items = []
    for k, v in value.items():
        if not isinstance(k, str) or not k:
            raise AlertManagerError(f"{what} keys must be non-empty str")
        if not isinstance(v, str):
            raise AlertManagerError(f"{what} values must be str")
        items.append((k, v))
    return tuple(sorted(items))


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


@dataclass(frozen=True)
class AlertRecord:
    """One fired alert, digest-pinned."""

    alert_id: str
    name: str
    labels: Tuple[Tuple[str, str], ...]
    severity: str
    annotations: Tuple[Tuple[str, str], ...]
    seq: int
    status: str
    digest: str
    version: str = ALERT_MANAGER_VERSION
    schema: str = ALERT_MANAGER_SCHEMA


@dataclass(frozen=True)
class ResolveRecord:
    """Record of an alert being resolved."""

    alert_id: str
    seq: int
    digest: str
    version: str = ALERT_MANAGER_VERSION
    schema: str = ALERT_MANAGER_SCHEMA


@dataclass(frozen=True)
class SilenceRecord:
    """One silence window over label matchers."""

    silence_id: str
    matchers: Tuple[Tuple[str, str], ...]
    starts_seq: int
    ends_seq: int
    comment: str
    seq: int
    active: bool
    digest: str
    version: str = ALERT_MANAGER_VERSION
    schema: str = ALERT_MANAGER_SCHEMA


@dataclass(frozen=True)
class ExpireRecord:
    """Record of a silence being expired early."""

    silence_id: str
    seq: int
    digest: str
    version: str = ALERT_MANAGER_VERSION
    schema: str = ALERT_MANAGER_SCHEMA


@dataclass(frozen=True)
class RouteRule:
    """One ordered routing rule: first match wins."""

    rule_id: str
    matchers: Tuple[Tuple[str, str], ...]
    receiver: str
    seq: int
    digest: str
    version: str = ALERT_MANAGER_VERSION
    schema: str = ALERT_MANAGER_SCHEMA


@dataclass(frozen=True)
class RoutedAlert:
    """Routing decision for one active alert."""

    alert_id: str
    receiver: str
    silenced: bool
    silence_id: Optional[str]
    seq: int
    digest: str
    version: str = ALERT_MANAGER_VERSION
    schema: str = ALERT_MANAGER_SCHEMA


@dataclass(frozen=True)
class RouteReport:
    """Frozen report of one route() pass."""

    seq: int
    routes: Tuple[RoutedAlert, ...]
    digest: str
    version: str = ALERT_MANAGER_VERSION
    schema: str = ALERT_MANAGER_SCHEMA


def alert_manager_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the alert manager."""
    if kind not in _KINDS:
        raise AlertManagerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "alert_manager",
        "module_version": ALERT_MANAGER_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


class AlertManager:
    """Alertmanager-shaped alert registry, silences, and routing."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._alerts: dict = {}  # alert_id -> _AlertState
        self._by_fingerprint: dict = {}  # (name, labels_digest) -> alert_id (active only)
        self._silences: dict = {}  # silence_id -> SilenceRecord
        self._rules: list = []  # RouteRule in insertion order
        self._next_alert = 0
        self._next_silence = 0
        self._next_rule = 0

    # -- alerts -----------------------------------------------------

    def fire(
        self,
        name: str,
        labels: Mapping[str, str],
        severity: str,
        seq: int,
        annotations: Optional[Mapping[str, str]] = None,
    ) -> AlertRecord:
        """Fire an alert. Idempotent while the same (name, labels) is active."""
        _check_str(name, "name")
        label_items = _check_str_map(labels, "labels")
        if not label_items:
            raise AlertManagerError("labels must name at least one label")
        if severity not in _SEVERITIES:
            raise AlertManagerError(f"severity must be one of {_SEVERITIES}")
        _check_seq(seq)
        annotation_items = (
            _check_str_map(annotations, "annotations") if annotations is not None else ()
        )

        fingerprint = (name, _pin(["labels"] + [list(label_items)]))
        with self._lock:
            existing_id = self._by_fingerprint.get(fingerprint)
            if existing_id is not None:
                return self._alerts[existing_id]["record"]  # dedup: already active
            self._next_alert += 1
            alert_id = f"alert-{self._next_alert}"
            digest = _pin(["alert", alert_id, name, [list(label_items)], severity,
                           [list(annotation_items)], seq])
            record = AlertRecord(
                alert_id=alert_id,
                name=name,
                labels=label_items,
                severity=severity,
                annotations=annotation_items,
                seq=seq,
                status=ACTIVE,
                digest=digest,
            )
            self._alerts[alert_id] = {"record": record, "fingerprint": fingerprint}
            self._by_fingerprint[fingerprint] = alert_id
            return record

    def resolve(self, alert_id: str, seq: int) -> ResolveRecord:
        """Resolve an active alert."""
        _check_str(alert_id, "alert_id")
        _check_seq(seq)
        with self._lock:
            state = self._alerts.get(alert_id)
            if state is None:
                raise UnknownAlertError(f"unknown alert: {alert_id!r}")
            if state["record"].status == RESOLVED:
                raise AlreadyResolvedError(f"alert already resolved: {alert_id!r}")
            old = state["record"]
            new_record = AlertRecord(
                alert_id=old.alert_id,
                name=old.name,
                labels=old.labels,
                severity=old.severity,
                annotations=old.annotations,
                seq=old.seq,
                status=RESOLVED,
                digest=old.digest,
            )
            state["record"] = new_record
            del self._by_fingerprint[state["fingerprint"]]
            digest = _pin(["resolve", alert_id, seq])
            return ResolveRecord(alert_id=alert_id, seq=seq, digest=digest)

    def alert(self, alert_id: str) -> AlertRecord:
        """Return the record for one alert."""
        _check_str(alert_id, "alert_id")
        with self._lock:
            state = self._alerts.get(alert_id)
            if state is None:
                raise UnknownAlertError(f"unknown alert: {alert_id!r}")
            return state["record"]

    def active_alerts(self) -> Tuple[AlertRecord, ...]:
        """All active alerts, sorted by alert id."""
        with self._lock:
            return tuple(
                sorted(
                    (s["record"] for s in self._alerts.values()
                     if s["record"].status == ACTIVE),
                    key=lambda r: r.alert_id,
                )
            )

    # -- silences ---------------------------------------------------

    def silence(
        self,
        matchers: Mapping[str, str],
        starts_seq: int,
        ends_seq: int,
        seq: int,
        comment: str = "",
    ) -> SilenceRecord:
        """Open a silence window over label matchers."""
        matcher_items = _check_str_map(matchers, "matchers")
        if not matcher_items:
            raise AlertManagerError("silence matchers must name at least one label")
        _check_seq(starts_seq, "starts_seq")
        _check_seq(ends_seq, "ends_seq")
        if ends_seq < starts_seq:
            raise AlertManagerError("ends_seq must be >= starts_seq")
        _check_seq(seq)
        if not isinstance(comment, str):
            raise AlertManagerError("comment must be a str")
        with self._lock:
            self._next_silence += 1
            silence_id = f"silence-{self._next_silence}"
            digest = _pin(["silence", silence_id, [list(matcher_items)],
                           starts_seq, ends_seq, seq])
            record = SilenceRecord(
                silence_id=silence_id,
                matchers=matcher_items,
                starts_seq=starts_seq,
                ends_seq=ends_seq,
                comment=comment,
                seq=seq,
                active=True,
                digest=digest,
            )
            self._silences[silence_id] = record
            return record

    def expire_silence(self, silence_id: str, seq: int) -> ExpireRecord:
        """Close a silence early."""
        _check_str(silence_id, "silence_id")
        _check_seq(seq)
        with self._lock:
            record = self._silences.get(silence_id)
            if record is None:
                raise UnknownSilenceError(f"unknown silence: {silence_id!r}")
            if not record.active:
                raise ExpiredSilenceError(f"silence already expired: {silence_id!r}")
            self._silences[silence_id] = SilenceRecord(
                silence_id=record.silence_id,
                matchers=record.matchers,
                starts_seq=record.starts_seq,
                ends_seq=record.ends_seq,
                comment=record.comment,
                seq=record.seq,
                active=False,
                digest=record.digest,
            )
            digest = _pin(["expire-silence", silence_id, seq])
            return ExpireRecord(silence_id=silence_id, seq=seq, digest=digest)

    def silences(self) -> Tuple[SilenceRecord, ...]:
        """All silences, sorted by silence id."""
        with self._lock:
            return tuple(sorted(self._silences.values(), key=lambda r: r.silence_id))

    # -- routing ----------------------------------------------------

    def add_route_rule(
        self, matchers: Mapping[str, str], receiver: str, seq: int
    ) -> RouteRule:
        """Append an ordered routing rule (first match wins)."""
        matcher_items = _check_str_map(matchers, "matchers")
        if not matcher_items:
            raise AlertManagerError("route matchers must name at least one label")
        _check_str(receiver, "receiver")
        _check_seq(seq)
        with self._lock:
            self._next_rule += 1
            rule_id = f"rule-{self._next_rule}"
            digest = _pin(["route-rule", rule_id, [list(matcher_items)], receiver, seq])
            rule = RouteRule(
                rule_id=rule_id,
                matchers=matcher_items,
                receiver=receiver,
                seq=seq,
                digest=digest,
            )
            self._rules.append(rule)
            return rule

    def rules(self) -> Tuple[RouteRule, ...]:
        """Routing rules in insertion order."""
        with self._lock:
            return tuple(self._rules)

    @staticmethod
    def _matches(matchers: Tuple[Tuple[str, str], ...],
                 labels: Tuple[Tuple[str, str], ...]) -> bool:
        label_map = dict(labels)
        return all(label_map.get(k) == v for k, v in matchers)

    def route(self, seq: int) -> RouteReport:
        """Compute the routing decision for every active alert at this seq."""
        _check_seq(seq)
        with self._lock:
            routed = []
            for record in self.active_alerts():
                silence_id = None
                for s in self._silences.values():
                    if (s.active and s.starts_seq <= seq <= s.ends_seq
                            and self._matches(s.matchers, record.labels)):
                        silence_id = s.silence_id
                        break
                receiver = DEFAULT_RECEIVER
                for rule in self._rules:
                    if self._matches(rule.matchers, record.labels):
                        receiver = rule.receiver
                        break
                digest = _pin(["routed", record.alert_id, receiver,
                               silence_id is not None, silence_id or "", seq])
                routed.append(RoutedAlert(
                    alert_id=record.alert_id,
                    receiver=receiver,
                    silenced=silence_id is not None,
                    silence_id=silence_id,
                    seq=seq,
                    digest=digest,
                ))
            digest = _pin(["route-report", seq, [r.digest for r in routed]])
            return RouteReport(seq=seq, routes=tuple(routed), digest=digest)


def main() -> None:
    am = AlertManager()
    a = am.fire("HighLatency", {"service": "api", "region": "us"}, CRITICAL, 1)
    b = am.fire("DiskFull", {"service": "db"}, WARNING, 2)
    assert am.fire("HighLatency", {"service": "api", "region": "us"},
                   CRITICAL, 3).alert_id == a.alert_id  # dedup
    s = am.silence({"service": "api"}, 0, 10, 4, comment="deploy")
    am.add_route_rule({"service": "db"}, "team-db-pager", 5)
    report = am.route(6)
    by_id = {r.alert_id: r for r in report.routes}
    assert by_id[a.alert_id].silenced and by_id[a.alert_id].silence_id == s.silence_id
    assert not by_id[b.alert_id].silenced
    assert by_id[b.alert_id].receiver == "team-db-pager"
    assert by_id[a.alert_id].receiver == DEFAULT_RECEIVER
    am.resolve(a.alert_id, 7)
    c = am.fire("HighLatency", {"service": "api", "region": "us"}, CRITICAL, 8)
    assert c.alert_id != a.alert_id  # re-fire after resolve is new
    alert_manager_audit_event(KIND_FIRED, 9, alert_id=c.alert_id)
    print("alert-manager OK: fire, dedup, silence, route, resolve")


if __name__ == "__main__":
    main()
