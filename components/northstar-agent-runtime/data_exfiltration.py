"""Data exfiltration detection/prevention ledger: book declared egress signals.

Distinct from siblings like ``egress_gate`` (which owns allow/deny
*enforcement* decisions on live calls) or ``dlp_*`` bookkeeping: this
module is the *detection and response decision ledger* for suspected
data exfiltration - it books host-declared signals, prevention actions,
and alert notifications as a deterministic single-host state machine.

* **Monitors** - ``monitor()`` declares one egress monitoring scope
  (``network-egress`` / ``usb`` / ``clipboard`` / ``print`` /
  ``api-call`` / ``file-transfer``). Monitor ids are never recycled.
* **Detections** - ``detect()`` books one declared exfiltration signal
  event (minted ``det-N`` ids): the signal travels over a pinned
  vocabulary, byte counts are booked as host-declared data, and the
  destination travels as a ``sha256:`` digest pin only.
* **Prevention** - ``prevent()`` books one declared response action
  per detection (``block`` / ``quarantine`` / ``throttle`` /
  ``alert-only`` / ``revoke-access`` / ``isolate-host``); unknown or
  already-prevented detections are refused fail-closed.
* **Alerts** - ``alert()`` books alert notifications (minted ``alr-N``
  ids) over the pinned channel vocabulary; an alert chain per detection
  is allowed.

Design (deterministic single-host ledger):
1. Frozen dataclasses, caller int seqs strictly increasing
   (claim-then-burn: failed mutations consume their seq + book
   ``data-exfiltration.rejected``; rewinds raise bare), no wall-clock,
   RLock-guarded, fail-closed taxonomy.
2. stdlib-only + the single ``canonical_json`` try/except fallback;
   ``sha256:`` digest pins with ``verify()``; ``audit.ndjson/1``
   events; version pin ``data-exfiltration.v1``; schema pin
   ``northstar.data-exfiltration.v1``.

Honest scope:
- This module books *declared* exfiltration events - it watches no
  network, inspects no bytes, and proves nothing about whether data
  really left the building.
- A booked ``detected`` record means "the host reported this signal",
  never "exfiltration happened". A booked ``blocked`` means "the host
  declared it blocked", never that anything was actually stopped.
- Digest pins prove ledger integrity and ordering, never the truth of
  the declared events.
- No persistence: the ledger is in-memory.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


VERSION = "data-exfiltration.v1"
SCHEMA = "northstar.data-exfiltration.v1"

KIND_MONITOR_REGISTERED = "monitor-registered"
KIND_DETECTED = "detected"
KIND_PREVENTED = "prevented"
KIND_ALERTED = "alerted"
KIND_REJECTED = "rejected"
_KINDS = frozenset({
    KIND_MONITOR_REGISTERED, KIND_DETECTED, KIND_PREVENTED,
    KIND_ALERTED, KIND_REJECTED,
})

_SCOPES = ("network-egress", "usb", "clipboard", "print",
           "api-call", "file-transfer")

_SIGNALS = ("bulk-transfer", "anomalous-egress", "unusual-destination",
            "off-hours-transfer", "large-attachment", "staged-archive")

_ACTIONS = ("block", "quarantine", "throttle", "alert-only",
            "revoke-access", "isolate-host")

_REASONS = ("policy", "dlp-rule", "analyst-decision", "auto-quarantine")

_CHANNELS = ("siem", "email", "pagerduty", "slack", "ticket")

_SEVERITIES = ("low", "medium", "high", "critical")

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Raw content must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset({
    "payload", "data", "content", "text", "raw", "file", "file_name",
    "filename", "bytes", "byte_count", "secret", "value", "exfiltrated",
    "destination", "host", "ip", "url",
})


class DataExfiltrationError(Exception):
    """Base class for all data-exfiltration ledger errors."""


class BadIdError(DataExfiltrationError):
    """Malformed monitor id, detection id, or alert id."""


class DuplicateMonitorError(DataExfiltrationError):
    """Monitor id already registered (ids are never recycled)."""


class UnknownMonitorError(DataExfiltrationError):
    """Monitor id not registered."""


class BadScopeError(DataExfiltrationError):
    """Scope not in the pinned vocabulary."""


class BadSignalError(DataExfiltrationError):
    """Signal not in the pinned vocabulary."""


class BadBytesError(DataExfiltrationError):
    """Byte count is not a non-negative int."""


class BadDigestError(DataExfiltrationError):
    """Digest is not a sha256:<64hex> pin (or empty)."""


class UnknownDetectionError(DataExfiltrationError):
    """Detection id not booked."""


class BadActionError(DataExfiltrationError):
    """Prevention action not in the pinned vocabulary."""


class BadReasonError(DataExfiltrationError):
    """Prevention reason not in the pinned vocabulary."""


class DuplicatePreventionError(DataExfiltrationError):
    """A prevention is already booked for this detection."""


class BadChannelError(DataExfiltrationError):
    """Alert channel not in the pinned vocabulary."""


class BadSeverityError(DataExfiltrationError):
    """Alert severity not in the pinned vocabulary."""


class UnknownAlertError(DataExfiltrationError):
    """Alert id not booked."""


class SeqOrderError(DataExfiltrationError):
    """Malformed seq or seq not strictly increasing."""


class AuditKindError(DataExfiltrationError):
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


def data_exfiltration_audit_event(kind: str, detail: Dict[str, object],
                                 seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the exfiltration ledger."""
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
        "kind": "data-exfiltration." + kind,
        "detail": dict(detail),
        "seq": seq,
    }


def _record_digest(tag: str, fields: Dict[str, object]) -> str:
    return _digest_pin({"data-exfiltration": tag, **fields})


@dataclass(frozen=True)
class MonitorRecord:
    """One declared egress monitoring scope."""

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
class DetectionRecord:
    """One declared exfiltration signal event.

    ``bytes_out`` is the host-declared byte count (bookkeeping data,
    never measured here). ``destination_pin`` pins the destination by
    digest only - the destination itself never enters a record.
    """

    det_id: str
    monitor_id: str
    signal: str
    bytes_out: int
    destination_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "det_id": self.det_id,
            "monitor_id": self.monitor_id,
            "signal": self.signal,
            "bytes_out": self.bytes_out,
            "destination_pin": self.destination_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("detection", {
            "det_id": self.det_id, "monitor_id": self.monitor_id,
            "signal": self.signal, "bytes_out": self.bytes_out,
            "destination_pin": self.destination_pin})


@dataclass(frozen=True)
class PreventionRecord:
    """One declared prevention action for a detection.

    At most one prevention per detection; the action is booked as a
    declared decision, never proof something was stopped.
    """

    det_id: str
    action: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "det_id": self.det_id,
            "action": self.action,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("prevention", {
            "det_id": self.det_id, "action": self.action,
            "reason": self.reason})


@dataclass(frozen=True)
class AlertRecord:
    """One declared alert notification for a detection."""

    alr_id: str
    det_id: str
    channel: str
    severity: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "alr_id": self.alr_id,
            "det_id": self.det_id,
            "channel": self.channel,
            "severity": self.severity,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("alert", {
            "alr_id": self.alr_id, "det_id": self.det_id,
            "channel": self.channel, "severity": self.severity})


class DataExfiltration:
    """Data exfiltration detection/prevention ledger.

    Simulated: books host-declared monitors, signal detections,
    prevention actions, and alerts. No network watching, no byte
    inspection, no wall-clock, no randomness.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._monitors: Dict[str, MonitorRecord] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._preventions: Dict[str, PreventionRecord] = {}
        self._alerts: Dict[str, AlertRecord] = {}
        self._det_counter = 0
        self._alr_counter = 0
        self._audit_log: List[Dict[str, object]] = []
        self._rejected = 0

    def _claim_seq(self, seq: int) -> None:
        """Claim-then-burn: seq must be strictly increasing."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be > {self._seq}, got {seq}")

    def _emit(self, kind: str, detail: Dict[str, object],
              seq: int) -> None:
        self._audit_log.append(
            data_exfiltration_audit_event(kind, detail, seq))

    def _reject(self, seq: int, what: str, why: str) -> None:
        self._rejected += 1
        self._emit(KIND_REJECTED,
                   {"what": what, "why": why}, seq)

    def monitor(self, monitor_id: object, scope: object,
                seq: object) -> MonitorRecord:
        """Declare one egress monitoring scope; fail-closed on misuse."""
        with self._lock:
            try:
                seq_v = _check_seq(seq)
                self._claim_seq(seq_v)
            except SeqOrderError:
                raise
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
                self._seq = seq_v
                self._emit(KIND_MONITOR_REGISTERED,
                           {"monitor_id": mid, "scope": scope}, seq_v)
                return rec
            except DataExfiltrationError as exc:
                self._seq = seq_v
                self._rejected += 1
                self._emit(KIND_REJECTED,
                           {"what": "monitor",
                            "why": type(exc).__name__}, seq_v)
                raise

    def detect(self, monitor_id: object, seq: object, signal: object,
               bytes_out: object = 0,
               destination_digest: object = "") -> DetectionRecord:
        """Book one declared exfiltration signal event (minted det-N)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _check_id(monitor_id, "monitor_id")
                if mid not in self._monitors:
                    raise UnknownMonitorError(
                        f"unknown monitor: {mid!r}")
                if not isinstance(signal, str) or signal not in _SIGNALS:
                    raise BadSignalError(
                        f"signal must be one of {sorted(_SIGNALS)}")
                if (isinstance(bytes_out, bool)
                        or not isinstance(bytes_out, int)
                        or bytes_out < 0):
                    raise BadBytesError(
                        "bytes_out must be a non-negative int")
                pin = _check_digest(destination_digest, "destination_digest")
                self._det_counter += 1
                det_id = f"det-{self._det_counter}"
                rec = DetectionRecord(
                    det_id=det_id, monitor_id=mid, signal=signal,
                    bytes_out=bytes_out, destination_pin=pin,
                    digest=_record_digest("detection", {
                        "det_id": det_id, "monitor_id": mid,
                        "signal": signal, "bytes_out": bytes_out,
                        "destination_pin": pin}))
                self._detections[det_id] = rec
                self._seq = seq_v
                self._emit(KIND_DETECTED,
                           {"det_id": det_id, "monitor_id": mid,
                            "signal": signal, "bytes_out": bytes_out},
                           seq_v)
                return rec
            except DataExfiltrationError as exc:
                self._seq = seq_v
                self._rejected += 1
                self._emit(KIND_REJECTED,
                           {"what": "detect",
                            "why": type(exc).__name__}, seq_v)
                raise

    def prevent(self, detection_id: object, seq: object, action: object,
                reason: object = "policy") -> PreventionRecord:
        """Book one declared prevention action for a detection.

        At most one prevention per detection; unknown detections and
        duplicate preventions are refused fail-closed.
        """
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                did = _check_id(detection_id, "detection_id")
                if did not in self._detections:
                    raise UnknownDetectionError(
                        f"unknown detection: {did!r}")
                if did in self._preventions:
                    raise DuplicatePreventionError(
                        f"detection already prevented: {did!r}")
                if not isinstance(action, str) or action not in _ACTIONS:
                    raise BadActionError(
                        f"action must be one of {sorted(_ACTIONS)}")
                if not isinstance(reason, str) or reason not in _REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(_REASONS)}")
                rec = PreventionRecord(
                    det_id=did, action=action, reason=reason,
                    digest=_record_digest("prevention", {
                        "det_id": did, "action": action,
                        "reason": reason}))
                self._preventions[did] = rec
                self._seq = seq_v
                self._emit(KIND_PREVENTED,
                           {"det_id": did, "action": action,
                            "reason": reason}, seq_v)
                return rec
            except DataExfiltrationError as exc:
                self._seq = seq_v
                self._rejected += 1
                self._emit(KIND_REJECTED,
                           {"what": "prevent",
                            "why": type(exc).__name__}, seq_v)
                raise

    def alert(self, detection_id: object, seq: object, channel: object,
              severity: object) -> AlertRecord:
        """Book one alert notification for a detection (minted alr-N)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                did = _check_id(detection_id, "detection_id")
                if did not in self._detections:
                    raise UnknownDetectionError(
                        f"unknown detection: {did!r}")
                if not isinstance(channel, str) or channel not in _CHANNELS:
                    raise BadChannelError(
                        f"channel must be one of {sorted(_CHANNELS)}")
                if not isinstance(severity, str) or severity not in _SEVERITIES:
                    raise BadSeverityError(
                        f"severity must be one of {sorted(_SEVERITIES)}")
                self._alr_counter += 1
                alr_id = f"alr-{self._alr_counter}"
                rec = AlertRecord(
                    alr_id=alr_id, det_id=did, channel=channel,
                    severity=severity,
                    digest=_record_digest("alert", {
                        "alr_id": alr_id, "det_id": did,
                        "channel": channel, "severity": severity}))
                self._alerts[alr_id] = rec
                self._seq = seq_v
                self._emit(KIND_ALERTED,
                           {"alr_id": alr_id, "det_id": did,
                            "channel": channel, "severity": severity},
                           seq_v)
                return rec
            except DataExfiltrationError as exc:
                self._seq = seq_v
                self._rejected += 1
                self._emit(KIND_REJECTED,
                           {"what": "alert",
                            "why": type(exc).__name__}, seq_v)
                raise

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

    def detection_record(self, detection_id: object,
                         seq: object) -> DetectionRecord:
        """Pure read: fetch one detection record (no seq consumption)."""
        with self._lock:
            _check_seq(seq)
            did = _check_id(detection_id, "detection_id")
            if did not in self._detections:
                raise UnknownDetectionError(
                    f"unknown detection: {did!r}")
            return self._detections[did]

    def detection_ids(self, seq: object) -> Tuple[str, ...]:
        """Pure read: all detection ids in booking order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._detections.keys())

    def detections_for(self, monitor_id: object,
                       seq: object) -> Tuple[str, ...]:
        """Pure read: detection ids booked under one monitor."""
        with self._lock:
            _check_seq(seq)
            mid = _check_id(monitor_id, "monitor_id")
            if mid not in self._monitors:
                raise UnknownMonitorError(
                    f"unknown monitor: {mid!r}")
            return tuple(d.det_id for d in self._detections.values()
                         if d.monitor_id == mid)

    def prevention_record(self, detection_id: object,
                          seq: object) -> PreventionRecord:
        """Pure read: fetch the prevention for a detection."""
        with self._lock:
            _check_seq(seq)
            did = _check_id(detection_id, "detection_id")
            if did not in self._preventions:
                raise UnknownDetectionError(
                    f"no prevention booked for: {did!r}")
            return self._preventions[did]

    def prevented_ids(self, seq: object) -> Tuple[str, ...]:
        """Pure read: detection ids with a booked prevention."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._preventions.keys())

    def alert_record(self, alert_id: object,
                     seq: object) -> AlertRecord:
        """Pure read: fetch one alert record (no seq consumption)."""
        with self._lock:
            _check_seq(seq)
            aid = _check_id(alert_id, "alert_id")
            if aid not in self._alerts:
                raise UnknownAlertError(f"unknown alert: {aid!r}")
            return self._alerts[aid]

    def alerts_for(self, detection_id: object,
                   seq: object) -> Tuple[str, ...]:
        """Pure read: alert ids booked for one detection."""
        with self._lock:
            _check_seq(seq)
            did = _check_id(detection_id, "detection_id")
            if did not in self._detections:
                raise UnknownDetectionError(
                    f"unknown detection: {did!r}")
            return tuple(a.alr_id for a in self._alerts.values()
                         if a.det_id == did)

    def stats(self, seq: object) -> Dict[str, int]:
        """Pure read: ledger counts."""
        with self._lock:
            _check_seq(seq)
            return {
                "monitors": len(self._monitors),
                "detections": len(self._detections),
                "preventions": len(self._preventions),
                "alerts": len(self._alerts),
                "rejected": self._rejected,
                "seq": self._seq,
            }

    def audit_log(self, seq: object) -> Tuple[Dict[str, object], ...]:
        """Pure read: the audit rows booked so far."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit_log)


def main() -> None:
    """Self-check smoke: monitor, detect, prevent, alert, pins, audit."""
    led = DataExfiltration()
    mon = led.monitor("m-net", "network-egress", 1)
    assert mon.verify()
    det = led.detect("m-net", 2, "bulk-transfer", bytes_out=1048576,
                     destination_digest="sha256:" + "a" * 64)
    assert det.verify()
    prv = led.prevent(det.det_id, 3, "block", reason="dlp-rule")
    assert prv.verify()
    alr = led.alert(det.det_id, 4, "siem", "high")
    assert alr.verify()
    led.stats(5)
    led.audit_log(5)
    assert len(led.audit_log(5)) == 4
    print("data-exfiltration OK: monitor, detect, prevent, alert, pins, audit")


if __name__ == "__main__":
    main()
