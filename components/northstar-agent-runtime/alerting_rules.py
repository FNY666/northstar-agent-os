"""Alerting rules — simulated Alertmanager/PagerDuty bookkeeping (thirty-fourth batch).

Research note (Alertmanager / PagerDuty incident-response literature):
Alertmanager books *routing rules* (receiver, matchers, group-wait),
*inhibit rules*, and *silences* (mute notifications matching a rule
for a bounded window). PagerDuty books *escalation policies* and
*urgency* (high/low) per incident; every notification is a record
that may or may not reach a human. This module takes the intersection
for a single-host deterministic ledger:

* **Rules, not pages**: ``rule`` books an alerting rule (name,
  pinned severity, pinned condition vocabulary, optional label
  matchers). No timers fire and no paging happens — firing is
  host-declared via ``notify``.
* **Notifications as data**: ``notify`` books a notification attempt
  against a rule and channel. The outcome (``delivered`` /
  ``suppressed``) is *data*, never raised. A notification record
  means "the host declared it sent", never that a human received it.
* **Silences, Alertmanager-faithful**: ``silence`` mutes a rule until
  a logical seq. A silenced rule still accepts ``notify`` calls; they
  are recorded as ``suppressed=True`` instead of being refused.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq; bool/
negative/rewind refused), RLock-guarded, fail-closed taxonomy,
stdlib-only (``canonical_json`` sibling helper behind the standard
try/except fallback), sha256 digest pins over type-tagged canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *declared* alerting state
deterministically. It cannot send an email, SMS, or page; it cannot
observe a recipient; it cannot prove a silence prevented an outage.
Pair with a real notification path and an on-call rotation for
production.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
ALERTING_RULES_VERSION = "alerting-rules.v1"

#: Schema pin carried by records and audit events.
ALERTING_RULES_SCHEMA = "northstar.alerting-rules.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned severity vocabulary (Alertmanager severity labels).
SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"
SEVERITIES = (SEVERITY_CRITICAL, SEVERITY_WARNING, SEVERITY_INFO)

#: Pinned condition vocabulary (what the rule watches).
CONDITION_THRESHOLD = "threshold"
CONDITION_HEARTBEAT = "heartbeat"
CONDITION_RATE_OF_CHANGE = "rate-of-change"
CONDITION_SLO_BURN_RATE = "slo-burn-rate"
CONDITIONS = (
    CONDITION_THRESHOLD,
    CONDITION_HEARTBEAT,
    CONDITION_RATE_OF_CHANGE,
    CONDITION_SLO_BURN_RATE,
)

#: Pinned notification channel vocabulary.
CHANNEL_EMAIL = "email"
CHANNEL_SMS = "sms"
CHANNEL_PAGERDUTY = "pagerduty"
CHANNEL_WEBHOOK = "webhook"
CHANNEL_SLACK = "slack"
CHANNELS = (
    CHANNEL_EMAIL,
    CHANNEL_SMS,
    CHANNEL_PAGERDUTY,
    CHANNEL_WEBHOOK,
    CHANNEL_SLACK,
)

#: Audit event kinds.
KIND_RULE_DEFINED = "alerting.rule-defined"
KIND_NOTIFIED = "alerting.notified"
KIND_SUPPRESSED = "alerting.suppressed"
KIND_SILENCED = "alerting.silenced"
KIND_SILENCE_LIFTED = "alerting.silence-lifted"
KIND_REJECTED = "alerting.rejected"
_KINDS = (
    KIND_RULE_DEFINED,
    KIND_NOTIFIED,
    KIND_SUPPRESSED,
    KIND_SILENCED,
    KIND_SILENCE_LIFTED,
    KIND_REJECTED,
)

_MAX_LABELS = 16
_MAX_STR = 256


# ---------------------------------------------------------------------------
# Fail-closed taxonomy
# ---------------------------------------------------------------------------


class AlertingRulesError(Exception):
    """Base error for the alerting-rules module."""


class BadRuleError(AlertingRulesError):
    """Rule definition was malformed."""


class DuplicateRuleError(AlertingRulesError):
    """A rule with this id already exists."""


class UnknownRuleError(AlertingRulesError):
    """No rule with this id is registered."""


class BadNotificationError(AlertingRulesError):
    """Notification request was malformed."""


class BadSilenceError(AlertingRulesError):
    """Silence request was malformed."""


class DuplicateSilenceError(AlertingRulesError):
    """A silence with this id already exists."""


class UnknownSilenceError(AlertingRulesError):
    """No silence with this id is registered."""


class SilenceStateError(AlertingRulesError):
    """Silence is in a state that forbids the operation."""


class SeqOrderError(AlertingRulesError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadRuleError(f"{name} must be a non-empty string")
    if len(value) > _MAX_STR:
        raise BadRuleError(f"{name} exceeds {_MAX_STR} chars")
    return value.strip()


def _check_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadRuleError("name must be a non-empty string")
    if len(value) > _MAX_STR:
        raise BadRuleError(f"name exceeds {_MAX_STR} chars")
    return value.strip()


def _check_severity(value: Any) -> str:
    if value not in SEVERITIES:
        raise BadRuleError(f"severity must be one of {SEVERITIES}")
    return value


def _check_condition(value: Any) -> str:
    if value not in CONDITIONS:
        raise BadRuleError(f"condition must be one of {CONDITIONS}")
    return value


def _check_channel(value: Any) -> str:
    if value not in CHANNELS:
        raise BadNotificationError(f"channel must be one of {CHANNELS}")
    return value


def _check_labels(labels: Any) -> tuple:
    if labels is None:
        return ()
    if not isinstance(labels, (tuple, list)) or len(labels) > _MAX_LABELS:
        raise BadRuleError("labels must be a list/tuple of 'key=value' strings")
    out = []
    for item in labels:
        if not isinstance(item, str) or "=" not in item:
            raise BadRuleError("labels must be 'key=value' strings")
        key, _, val = item.partition("=")
        key, val = key.strip(), val.strip()
        if not key or not val or len(item) > _MAX_STR:
            raise BadRuleError("label keys and values must be non-empty")
        if any(c.isspace() or c in "{}\"'\\" for c in key):
            raise BadRuleError(f"bad label key: {key!r}")
        out.append(f"{key}={val}")
    return tuple(sorted(out))


def _check_recipient(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadNotificationError("recipient must be a non-empty string")
    if len(value) > _MAX_STR:
        raise BadNotificationError(f"recipient exceeds {_MAX_STR} chars")
    return value.strip()


def _check_reason(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadSilenceError("reason must be a non-empty string")
    if len(value) > _MAX_STR:
        raise BadSilenceError(f"reason exceeds {_MAX_STR} chars")
    return value.strip()


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(_canonical([ALERTING_RULES_VERSION, *parts])).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleRecord:
    """One pinned alerting rule (frozen)."""

    rule_id: str
    name: str
    severity: str
    condition: str
    labels: tuple
    seq: int
    digest: str
    schema: str = ALERTING_RULES_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "rule", self.rule_id, self.name, self.severity,
            self.condition, list(self.labels), self.seq,
        )


@dataclass(frozen=True)
class NotificationRecord:
    """One booked notification attempt (frozen). ``suppressed`` is data."""

    notification_id: str
    rule_id: str
    channel: str
    suppressed: bool
    seq: int
    digest: str
    schema: str = ALERTING_RULES_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "notify", self.notification_id, self.rule_id, self.channel,
            self.suppressed, self.seq,
        )


@dataclass(frozen=True)
class SilenceRecord:
    """One Alertmanager-style silence (frozen). ``lifted`` is data."""

    silence_id: str
    rule_id: str
    until_seq: int
    lifted: bool
    seq: int
    digest: str
    schema: str = ALERTING_RULES_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "silence", self.silence_id, self.rule_id, self.until_seq,
            self.lifted, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def alerting_rules_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> dict:
    """Shape an ``audit.ndjson/1`` record for the alerting-rules module."""
    if kind not in _KINDS:
        raise AlertingRulesError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise AlertingRulesError("detail must be a mapping")
    # Recipients, messages, reasons never cross the audit boundary;
    # only ids and digest pins.
    banned = {"recipient", "message", "reason", "labels"}
    if any(k in detail for k in banned):
        raise AlertingRulesError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": ALERTING_RULES_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class AlertingRules:
    """Deterministic alerting-rule/notification/silence ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._rules: dict[str, RuleRecord] = {}
        self._notifications: dict[str, NotificationRecord] = {}
        self._silences: dict[str, SilenceRecord] = {}
        self._counter = 0
        self._audit: list = []

    # -- internals ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must strictly increase (got {seq}, last {self._seq})"
            )
        self._seq = seq
        return seq

    def _emit(self, kind: str, detail: Mapping[str, Any], seq: int) -> None:
        self._audit.append(alerting_rules_audit_event(kind, detail, seq))

    def _reject(self, reason: str, seq: int) -> None:
        self._emit(KIND_REJECTED, {"error": reason}, seq)

    def _next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter}"

    def _silenced_at(self, rule_id: str, seq: int) -> bool:
        return any(
            s.rule_id == rule_id and not s.lifted and s.until_seq > seq
            for s in self._silences.values()
        )

    # -- rules ----------------------------------------------------------

    def rule(
        self,
        rule_id: str,
        name: str,
        severity: str,
        condition: str,
        seq: int,
        labels: Sequence[str] | None = None,
    ) -> RuleRecord:
        """Define an alerting rule (frozen record)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                rid = _check_id(rule_id, "rule_id")
                nm = _check_name(name)
                sev = _check_severity(severity)
                cond = _check_condition(condition)
                lbs = _check_labels(labels)
            except AlertingRulesError as exc:
                self._reject(str(exc), seq)
                raise
            if rid in self._rules:
                self._reject(f"duplicate rule: {rid}", seq)
                raise DuplicateRuleError(f"rule already exists: {rid}")
            rec = RuleRecord(
                rule_id=rid,
                name=nm,
                severity=sev,
                condition=cond,
                labels=lbs,
                seq=seq,
                digest=_pin(
                    "rule", rid, nm, sev, cond, list(lbs), seq
                ),
            )
            self._rules[rid] = rec
            self._emit(
                KIND_RULE_DEFINED,
                {"rule_id": rid, "severity": sev, "condition": cond},
                seq,
            )
            return rec

    # -- notifications --------------------------------------------------

    def notify(
        self, rule_id: str, seq: int, channel: str, recipient: str
    ) -> NotificationRecord:
        """Book a notification attempt.

        Returns the outcome as *data*: ``suppressed=True`` when an
        active silence covers the rule at ``seq`` (Alertmanager-faithful
        suppression), ``False`` otherwise. Never raises for silencing.
        """
        with self._lock:
            seq = self._next_seq(seq)
            try:
                rid = _check_id(rule_id, "rule_id")
                ch = _check_channel(channel)
                _check_recipient(recipient)
            except AlertingRulesError as exc:
                self._reject(str(exc), seq)
                raise
            if rid not in self._rules:
                self._reject(f"unknown rule: {rid}", seq)
                raise UnknownRuleError(f"unknown rule: {rid}")
            nid = self._next_id("ntf")
            suppressed = self._silenced_at(rid, seq)
            rec = NotificationRecord(
                notification_id=nid,
                rule_id=rid,
                channel=ch,
                suppressed=suppressed,
                seq=seq,
                digest=_pin("notify", nid, rid, ch, suppressed, seq),
            )
            self._notifications[nid] = rec
            self._emit(
                KIND_SUPPRESSED if suppressed else KIND_NOTIFIED,
                {
                    "notification_id": nid,
                    "rule_id": rid,
                    "channel": ch,
                    "suppressed": suppressed,
                },
                seq,
            )
            return rec

    # -- silences -------------------------------------------------------

    def silence(
        self,
        silence_id: str,
        rule_id: str,
        seq: int,
        until_seq: int,
        reason: str,
    ) -> SilenceRecord:
        """Mute a rule until ``until_seq`` (Alertmanager-style silence)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                sid = _check_id(silence_id, "silence_id")
                rid = _check_id(rule_id, "rule_id")
                _check_seq(until_seq, "until_seq")
                rsn = _check_reason(reason)
            except AlertingRulesError as exc:
                self._reject(str(exc), seq)
                raise
            if until_seq <= seq:
                self._reject("until_seq must be after seq", seq)
                raise BadSilenceError("until_seq must be after seq")
            if rid not in self._rules:
                self._reject(f"unknown rule: {rid}", seq)
                raise UnknownRuleError(f"unknown rule: {rid}")
            if sid in self._silences:
                self._reject(f"duplicate silence: {sid}", seq)
                raise DuplicateSilenceError(f"silence already exists: {sid}")
            rec = SilenceRecord(
                silence_id=sid,
                rule_id=rid,
                until_seq=until_seq,
                lifted=False,
                seq=seq,
                digest=_pin("silence", sid, rid, until_seq, False, seq),
            )
            self._silences[sid] = rec
            # reason stays out of the audit boundary (banned key)
            self._emit(
                KIND_SILENCED,
                {"silence_id": sid, "rule_id": rid, "until_seq": until_seq},
                seq,
            )
            return rec

    def lift_silence(self, silence_id: str, seq: int) -> SilenceRecord:
        """Lift a silence early (frozen replacement record)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                sid = _check_id(silence_id, "silence_id")
            except AlertingRulesError as exc:
                self._reject(str(exc), seq)
                raise
            if sid not in self._silences:
                self._reject(f"unknown silence: {sid}", seq)
                raise UnknownSilenceError(f"unknown silence: {sid}")
            old = self._silences[sid]
            if old.lifted:
                self._reject(f"silence already lifted: {sid}", seq)
                raise SilenceStateError(f"silence already lifted: {sid}")
            rec = SilenceRecord(
                silence_id=sid,
                rule_id=old.rule_id,
                until_seq=old.until_seq,
                lifted=True,
                seq=seq,
                digest=_pin("silence", sid, old.rule_id, old.until_seq, True, seq),
            )
            self._silences[sid] = rec
            self._emit(
                KIND_SILENCE_LIFTED,
                {"silence_id": sid, "rule_id": old.rule_id},
                seq,
            )
            return rec

    # -- pure views -----------------------------------------------------

    def rule_record(self, rule_id: str) -> RuleRecord:
        with self._lock:
            if rule_id not in self._rules:
                raise UnknownRuleError(f"unknown rule: {rule_id}")
            return self._rules[rule_id]

    def rule_ids(self) -> tuple:
        with self._lock:
            return tuple(sorted(self._rules))

    def notification(self, notification_id: str) -> NotificationRecord:
        with self._lock:
            if notification_id not in self._notifications:
                raise BadNotificationError(f"unknown notification: {notification_id}")
            return self._notifications[notification_id]

    def notifications_for(self, rule_id: str) -> tuple:
        with self._lock:
            if rule_id not in self._rules:
                raise UnknownRuleError(f"unknown rule: {rule_id}")
            return tuple(
                n
                for n in self._notifications.values()
                if n.rule_id == rule_id
            )

    def silence_record(self, silence_id: str) -> SilenceRecord:
        with self._lock:
            if silence_id not in self._silences:
                raise UnknownSilenceError(f"unknown silence: {silence_id}")
            return self._silences[silence_id]

    def active_silences(self, rule_id: str, seq: int) -> tuple:
        """Silences covering ``rule_id`` at ``seq`` (pure view)."""
        with self._lock:
            _check_seq(seq, "seq")
            if rule_id not in self._rules:
                raise UnknownRuleError(f"unknown rule: {rule_id}")
            return tuple(
                s
                for s in self._silences.values()
                if s.rule_id == rule_id and not s.lifted and s.until_seq > seq
            )

    def stats(self) -> dict:
        with self._lock:
            return {
                "rules": len(self._rules),
                "notifications": len(self._notifications),
                "suppressed": sum(1 for n in self._notifications.values() if n.suppressed),
                "silences": len(self._silences),
                "seq": self._seq,
            }

    def audit_log(self) -> tuple:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    ar = AlertingRules()
    ar.rule("r1", "api-latency", "critical", "threshold", 1, labels=["team=oncall"])
    n1 = ar.notify("r1", 2, "pagerduty", "oncall@example.com")
    assert not n1.suppressed
    ar.silence("s1", "r1", 3, 100, "deploy freeze")
    n2 = ar.notify("r1", 4, "email", "team@example.com")
    assert n2.suppressed
    ar.lift_silence("s1", 5)
    n3 = ar.notify("r1", 6, "slack", "#alerts")
    assert not n3.suppressed
    assert all(r.verify() for r in (ar.rule_record("r1"),))
    assert all(n.verify() for n in (n1, n2, n3))
    assert ar.silence_record("s1").verify()
    print("alerting-rules OK: rule, notify, silence, lift, suppress, pins, audit")


if __name__ == "__main__":
    main()
