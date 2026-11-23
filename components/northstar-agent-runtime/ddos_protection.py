"""DDoS attack detection and mitigation bookkeeping.

A ``DDoSProtection`` ledger books host-reported DDoS defense decisions as
a deterministic single-host state machine:

- ``define_profile(profile_id, attack_types, thresholds, seq)`` pins a
  detection profile: per-metric ``(warn, crit)`` bounds over a pinned
  7-metric vocabulary, plus the warn/attack score cutoffs.
- ``detect(source_id, profile_id, counters, seq)`` classifies one
  host-reported traffic snapshot. The verdict (``normal`` / ``suspect``
  / ``attack``) and the attributed attack type are *data*, never raised.
  Sources covered by an active allowlist entry bypass classification
  (``allowlisted=True``).
- ``mitigate(target_id, detection_id, level, seq)`` activates a
  mitigation for a target, gated fail-closed on a referenced detection
  whose verdict is ``attack``. One active mitigation per target; it is
  terminal until ``stand_down()``.
- ``stand_down(target_id, seq, reason)`` ends the active mitigation.
- ``allowlist(entry_id, identity, seq, reason)`` /
  ``remove_allowlist(entry_id, seq, reason)`` manage trusted-source
  bypass entries (``ip:`` / ``cidr:`` / ``host:`` / ``asn:``).

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin ``ddos-protection.v1``,
schema pin ``northstar.ddos-protection.v1``, ``main()`` self-check.

Honest scope: this module books *host-reported* traffic counters and
cannot observe the wire, cannot prove a source is really attacking, and
cannot prove an attack is absent — a ``normal`` verdict means "no known
attack shape in the reported counters", never "no attack". Detection is a
pinned-threshold heuristic, not a learned model; mitigation records the
*decision*, it performs no traffic shaping. Pair with real telemetry and
an actual scrubbing path in production.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
DDOS_VERSION = "ddos-protection.v1"

#: Schema pin carried by records and audit events.
DDOS_SCHEMA = "northstar.ddos-protection.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Attack shapes the classifier can attribute (profiles pin a subset).
ATTACK_TYPES = ("volumetric-flood", "syn-flood", "slowloris", "amplification")

#: Host-reported traffic metrics the classifier scores.
METRICS = (
    "requests",
    "unique_sources",
    "syn_ratio",
    "slow_connections",
    "amplification_factor",
    "bandwidth_bytes",
    "error_rate",
)

#: Metrics bounded to [0, 1].
RATIO_METRICS = ("syn_ratio", "error_rate")

#: Which attack type each metric evidences; None = type-neutral score only.
METRIC_ATTACK_TYPE = {
    "requests": "volumetric-flood",
    "unique_sources": "volumetric-flood",
    "bandwidth_bytes": "volumetric-flood",
    "syn_ratio": "syn-flood",
    "slow_connections": "slowloris",
    "amplification_factor": "amplification",
    "error_rate": None,
}

#: Detection verdicts (data, never raised).
VERDICTS = ("normal", "suspect", "attack")

#: Special attack_type values on a DetectionReport.
ATTACK_TYPE_NONE = "none"
ATTACK_TYPE_MIXED = "mixed"
ATTACK_TYPE_UNKNOWN = "unknown-shape"

#: Mitigation postures, weakest to strongest.
MITIGATION_LEVELS = ("monitor", "challenge", "throttle", "scrub", "blackhole")


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class DDoSProtectionError(ValueError):
    """Base for all ddos-protection structural problems and refused transitions."""


class BadProfileError(DDoSProtectionError):
    """Profile definition is malformed (bad id, type, thresholds, scores)."""


class UnknownProfileError(DDoSProtectionError):
    """No profile is pinned for the requested id."""


class DuplicateProfileError(DDoSProtectionError):
    """A profile id is already registered."""


class BadCountersError(DDoSProtectionError):
    """Traffic counters are malformed (bad metric, value, or shape)."""


class UnknownDetectionError(DDoSProtectionError):
    """No detection report exists for the requested id."""


class BadMitigationError(DDoSProtectionError):
    """Mitigation request is malformed or unjustified (bad level, target,
    or referenced detection verdict is not ``attack``)."""


class ActiveMitigationError(DDoSProtectionError):
    """The target already has an active mitigation; stand down first."""


class UnknownMitigationError(DDoSProtectionError):
    """No active mitigation for the target."""


class BadAllowlistError(DDoSProtectionError):
    """Allowlist entry is malformed (bad id or identity shape)."""


class DuplicateAllowlistError(DDoSProtectionError):
    """An allowlist entry id is already registered."""


class UnknownAllowlistError(DDoSProtectionError):
    """No allowlist entry exists for the requested id."""


class SeqOrderError(DDoSProtectionError):
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
        raise DDoSProtectionError(f"{name} must be a non-empty string")
    return value.strip()


def _check_number(value: Any, name: str, exc: Any = None) -> float:
    error = exc or DDoSProtectionError
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise error(f"{name} must be a number")
    if math.isnan(value) or math.isinf(value):
        raise error(f"{name} must be finite")
    if value < 0:
        raise error(f"{name} must be non-negative")
    return value


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([DDOS_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricThreshold:
    """One pinned (warn, crit) bound for a metric (frozen)."""

    metric: str
    warn: float
    crit: float

    def as_tuple(self) -> Tuple[str, float, float]:
        return (self.metric, self.warn, self.crit)


@dataclass(frozen=True)
class MetricResult:
    """One scored metric inside a detection report (frozen)."""

    metric: str
    value: float
    points: int
    level: str  # ok | warn | crit


@dataclass(frozen=True)
class ProfileRecord:
    """One pinned detection profile (frozen)."""

    profile_id: str
    attack_types: Tuple[str, ...]
    thresholds: Tuple[MetricThreshold, ...]
    warn_score: int
    crit_score: int
    seq: int
    digest: str
    schema: str = DDOS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "profile",
            self.profile_id,
            self.attack_types,
            tuple(t.as_tuple() for t in self.thresholds),
            self.warn_score,
            self.crit_score,
            self.seq,
        )


@dataclass(frozen=True)
class DetectionReport:
    """One traffic-snapshot classification (frozen). Verdict is data."""

    detection_id: str
    source_id: str
    profile_id: str
    verdict: str
    attack_type: str
    score: int
    results: Tuple[MetricResult, ...]
    allowlisted: bool
    seq: int
    digest: str
    schema: str = DDOS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "detect",
            self.detection_id,
            self.source_id,
            self.profile_id,
            self.verdict,
            self.attack_type,
            self.score,
            tuple((r.metric, r.value, r.points, r.level) for r in self.results),
            self.allowlisted,
            self.seq,
        )


@dataclass(frozen=True)
class MitigationRecord:
    """One active mitigation (frozen). Terminal until stand-down."""

    mitigation_id: str
    target_id: str
    detection_id: str
    level: str
    status: str  # always "active" while stored
    seq: int
    digest: str
    schema: str = DDOS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "mitigate",
            self.mitigation_id,
            self.target_id,
            self.detection_id,
            self.level,
            self.status,
            self.seq,
        )


@dataclass(frozen=True)
class StandDownRecord:
    """One mitigation stand-down (frozen)."""

    target_id: str
    mitigation_id: str
    reason: str
    seq: int
    digest: str
    schema: str = DDOS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "stand-down", self.target_id, self.mitigation_id, self.reason,
            self.seq,
        )


@dataclass(frozen=True)
class AllowlistRecord:
    """One trusted-source bypass entry (frozen). Removal is terminal."""

    entry_id: str
    identity: str
    reason: str
    seq: int
    active: bool
    digest: str
    schema: str = DDOS_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "allowlist", self.entry_id, self.identity, self.reason, self.seq,
            self.active,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_PROFILE_DEFINED = "ddos.profile-defined"
KIND_DETECTED = "ddos.detected"
KIND_MITIGATED = "ddos.mitigated"
KIND_STOOD_DOWN = "ddos.stood-down"
KIND_ALLOWLISTED = "ddos.allowlisted"
KIND_ALLOWLIST_REMOVED = "ddos.allowlist-removed"
KIND_REJECTED = "ddos.rejected"
_KINDS = (
    KIND_PROFILE_DEFINED,
    KIND_DETECTED,
    KIND_MITIGATED,
    KIND_STOOD_DOWN,
    KIND_ALLOWLISTED,
    KIND_ALLOWLIST_REMOVED,
    KIND_REJECTED,
)


def ddos_protection_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the ddos-protection module."""
    if kind not in _KINDS:
        raise DDoSProtectionError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise DDoSProtectionError("detail must be a mapping")
    # Raw traffic counters and source identities never cross the audit
    # boundary; ids, digests, scores, and verdicts only.
    banned = {"counters", "identity"}
    if any(k in detail for k in banned):
        raise DDoSProtectionError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": DDOS_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# Identity helpers (allowlist)
# ---------------------------------------------------------------------------


def _parse_identity(identity: str) -> Tuple[str, Any]:
    """Parse ``ip:`` / ``cidr:`` / ``host:`` / ``asn:`` identity shapes."""
    if identity.startswith("ip:"):
        try:
            return ("ip", ipaddress.ip_address(identity[3:]))
        except ValueError:
            raise BadAllowlistError(f"bad ip identity: {identity!r}")
    if identity.startswith("cidr:"):
        try:
            return ("cidr", ipaddress.ip_network(identity[5:], strict=False))
        except ValueError:
            raise BadAllowlistError(f"bad cidr identity: {identity!r}")
    if identity.startswith("host:"):
        host = identity[5:].strip().lower()
        if not host or any(c.isspace() for c in host):
            raise BadAllowlistError(f"bad host identity: {identity!r}")
        return ("host", host)
    if identity.startswith("asn:"):
        asn = identity[4:].strip().upper()
        if not (asn.startswith("AS") and len(asn) > 2 and asn[2:].isdigit()):
            raise BadAllowlistError(f"bad asn identity: {identity!r}")
        return ("asn", asn)
    raise BadAllowlistError(
        "identity must be ip:<addr>, cidr:<net>, host:<name>, or asn:AS<n>"
    )


def _identity_covers(kind: str, value: Any, source_id: str) -> bool:
    """True when an allowlist entry covers the detection source."""
    if kind == "ip":
        return source_id == f"ip:{value}"
    if kind == "cidr":
        if source_id.startswith("ip:"):
            try:
                return ipaddress.ip_address(source_id[3:]) in value
            except ValueError:
                return False
        return False
    if kind == "host":
        return source_id.strip().lower() == f"host:{value}"
    if kind == "asn":
        return source_id.strip().upper() == f"ASN:{value}"
    return False


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class DDoSProtection:
    """Deterministic DDoS detection/mitigation/allowlist ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._profiles: Dict[str, ProfileRecord] = {}
        self._detections: Dict[str, DetectionReport] = {}
        self._detect_seq = 0
        self._mitigations: Dict[str, MitigationRecord] = {}  # target -> active
        self._mit_seq = 0
        self._past_mitigations: List[MitigationRecord] = []
        self._stand_downs: List[StandDownRecord] = []
        self._allowlist: Dict[str, AllowlistRecord] = {}
        self._allowlist_parsed: Dict[str, Tuple[str, Any]] = {}
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
        self._audit.append(ddos_protection_audit_event(kind, detail, self._last_seq))

    def _reject_locked(self, reason: str) -> None:
        self._audit_locked(KIND_REJECTED, {"reason": reason})

    def _check_thresholds_locked(
        self, thresholds: Mapping[str, Any]
    ) -> Tuple[MetricThreshold, ...]:
        if not isinstance(thresholds, Mapping) or not thresholds:
            raise BadProfileError("thresholds must be a non-empty mapping")
        parsed: List[MetricThreshold] = []
        for metric, bounds in thresholds.items():
            if metric not in METRICS:
                raise BadProfileError(f"unknown metric: {metric!r}")
            if (
                not isinstance(bounds, (tuple, list))
                or len(bounds) != 2
            ):
                raise BadProfileError(
                    f"threshold for {metric!r} must be (warn, crit)"
                )
            warn, crit = bounds
            warn = _check_number(warn, f"warn({metric})", BadProfileError)
            crit = _check_number(crit, f"crit({metric})", BadProfileError)
            if not warn < crit:
                raise BadProfileError(
                    f"warn must be < crit for {metric!r}"
                )
            if metric in RATIO_METRICS and crit > 1:
                raise BadProfileError(
                    f"crit for ratio metric {metric!r} must be <= 1"
                )
            parsed.append(MetricThreshold(metric, warn, crit))
        names = [t.metric for t in parsed]
        if len(set(names)) != len(names):
            raise BadProfileError("duplicate metric in thresholds")
        return tuple(sorted(parsed, key=lambda t: t.metric))

    def _check_counters_locked(
        self, counters: Mapping[str, Any]
    ) -> Dict[str, float]:
        if not isinstance(counters, Mapping) or not counters:
            raise BadCountersError("counters must be a non-empty mapping")
        clean: Dict[str, float] = {}
        for metric, value in counters.items():
            if metric not in METRICS:
                raise BadCountersError(f"unknown metric: {metric!r}")
            clean[metric] = _check_number(
                value, f"counters[{metric}]", BadCountersError
            )
        return clean

    def _classify_locked(
        self, profile: ProfileRecord, counters: Dict[str, float]
    ) -> Tuple[str, str, int, Tuple[MetricResult, ...]]:
        score = 0
        type_points = {t: 0 for t in ATTACK_TYPES}
        type_crit = {t: 0 for t in ATTACK_TYPES}
        results: List[MetricResult] = []
        for th in profile.thresholds:
            if th.metric not in counters:
                continue
            value = counters[th.metric]
            if value >= th.crit:
                points, level = 2, "crit"
            elif value >= th.warn:
                points, level = 1, "warn"
            else:
                points, level = 0, "ok"
            score += points
            attack_type = METRIC_ATTACK_TYPE[th.metric]
            if attack_type is not None and attack_type in profile.attack_types:
                type_points[attack_type] += points
                if level == "crit":
                    type_crit[attack_type] += 1
            results.append(MetricResult(th.metric, value, points, level))
        if score >= profile.crit_score:
            verdict = "attack"
        elif score >= profile.warn_score:
            verdict = "suspect"
        else:
            verdict = "normal"
        if verdict == "attack":
            ranked = sorted(
                (
                    (t, type_crit[t], type_points[t])
                    for t in profile.attack_types
                    if type_points[t] > 0
                ),
                key=lambda row: (row[1], row[2]),
                reverse=True,
            )
            if not ranked:
                attack_type = ATTACK_TYPE_UNKNOWN
            elif (
                len(ranked) > 1
                and ranked[0][1] == ranked[1][1]
                and ranked[0][2] == ranked[1][2]
            ):
                attack_type = ATTACK_TYPE_MIXED
            else:
                attack_type = ranked[0][0]
        else:
            attack_type = ATTACK_TYPE_NONE
        return verdict, attack_type, score, tuple(results)

    # -- profiles -------------------------------------------------------

    def define_profile(
        self,
        profile_id: str,
        attack_types: Any,
        thresholds: Mapping[str, Any],
        seq: int,
        *,
        warn_score: int = 2,
        crit_score: int = 4,
    ) -> ProfileRecord:
        """Pin a detection profile: attack types, metric bounds, cutoffs."""
        _check_seq(seq, "seq")
        profile_id = _check_nonempty_str(profile_id, "profile_id")
        self._claim_seq(seq)
        with self._lock:
            if isinstance(attack_types, str):
                attack_types = (attack_types,)
            if not isinstance(attack_types, (tuple, list)) or not attack_types:
                self._reject_locked("bad-attack-types")
                raise BadProfileError("attack_types must be a non-empty list")
            attack_types = tuple(attack_types)
            for attack_type in attack_types:
                if attack_type not in ATTACK_TYPES:
                    self._reject_locked("unknown-attack-type")
                    raise BadProfileError(
                        f"unknown attack type: {attack_type!r}"
                    )
            if len(set(attack_types)) != len(attack_types):
                self._reject_locked("duplicate-attack-type")
                raise BadProfileError("duplicate attack type")
            try:
                parsed_thresholds = self._check_thresholds_locked(thresholds)
            except BadProfileError:
                self._reject_locked("bad-thresholds")
                raise
            for name, value in (("warn_score", warn_score), ("crit_score", crit_score)):
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    self._reject_locked("bad-score")
                    raise BadProfileError(f"{name} must be a positive int")
            if not warn_score < crit_score:
                self._reject_locked("bad-score-order")
                raise BadProfileError("warn_score must be < crit_score")
            if profile_id in self._profiles:
                self._reject_locked("duplicate-profile")
                raise DuplicateProfileError(
                    f"profile {profile_id!r} already defined"
                )
            record = ProfileRecord(
                profile_id=profile_id,
                attack_types=attack_types,
                thresholds=parsed_thresholds,
                warn_score=warn_score,
                crit_score=crit_score,
                seq=seq,
                digest=_pin(
                    "profile",
                    profile_id,
                    attack_types,
                    tuple(t.as_tuple() for t in parsed_thresholds),
                    warn_score,
                    crit_score,
                    seq,
                ),
            )
            self._profiles[profile_id] = record
            self._audit_locked(
                KIND_PROFILE_DEFINED,
                {"profile_id": profile_id, "digest": record.digest},
            )
            return record

    # -- detection ------------------------------------------------------

    def detect(
        self,
        source_id: str,
        profile_id: str,
        counters: Mapping[str, Any],
        seq: int,
    ) -> DetectionReport:
        """Classify one host-reported traffic snapshot.

        The verdict is data (``normal`` / ``suspect`` / ``attack``), never
        raised. Sources covered by an active allowlist entry bypass
        classification (``allowlisted=True``).
        """
        _check_seq(seq, "seq")
        source_id = _check_nonempty_str(source_id, "source_id")
        profile_id = _check_nonempty_str(profile_id, "profile_id")
        self._claim_seq(seq)
        with self._lock:
            profile = self._profiles.get(profile_id)
            if profile is None:
                self._reject_locked("unknown-profile")
                raise UnknownProfileError(f"unknown profile {profile_id!r}")
            try:
                clean = self._check_counters_locked(counters)
            except BadCountersError:
                self._reject_locked("bad-counters")
                raise
            self._detect_seq += 1
            detection_id = f"det-{self._detect_seq}"
            allowlisted = any(
                _identity_covers(kind, value, source_id)
                for kind, value in self._allowlist_parsed.values()
            )
            if allowlisted:
                verdict, attack_type, score = "normal", ATTACK_TYPE_NONE, 0
                results: Tuple[MetricResult, ...] = ()
            else:
                verdict, attack_type, score, results = self._classify_locked(
                    profile, clean
                )
            report = DetectionReport(
                detection_id=detection_id,
                source_id=source_id,
                profile_id=profile_id,
                verdict=verdict,
                attack_type=attack_type,
                score=score,
                results=results,
                allowlisted=allowlisted,
                seq=seq,
                digest=_pin(
                    "detect",
                    detection_id,
                    source_id,
                    profile_id,
                    verdict,
                    attack_type,
                    score,
                    tuple(
                        (r.metric, r.value, r.points, r.level) for r in results
                    ),
                    allowlisted,
                    seq,
                ),
            )
            self._detections[detection_id] = report
            self._audit_locked(
                KIND_DETECTED,
                {
                    "detection_id": detection_id,
                    "profile_id": profile_id,
                    "verdict": verdict,
                    "attack_type": attack_type,
                    "score": score,
                    "allowlisted": allowlisted,
                    "digest": report.digest,
                },
            )
            return report

    # -- mitigation -----------------------------------------------------

    def mitigate(
        self,
        target_id: str,
        detection_id: str,
        level: str,
        seq: int,
        reason: str = "",
    ) -> MitigationRecord:
        """Activate a mitigation for a target.

        Fail-closed: the referenced detection must exist and its verdict
        must be ``attack``. One active mitigation per target; stand down
        before re-mitigating.
        """
        _check_seq(seq, "seq")
        target_id = _check_nonempty_str(target_id, "target_id")
        detection_id = _check_nonempty_str(detection_id, "detection_id")
        self._claim_seq(seq)
        with self._lock:
            if level not in MITIGATION_LEVELS:
                self._reject_locked("unknown-level")
                raise BadMitigationError(f"unknown level: {level!r}")
            reason = reason.strip() if isinstance(reason, str) else ""
            detection = self._detections.get(detection_id)
            if detection is None:
                self._reject_locked("unknown-detection")
                raise UnknownDetectionError(
                    f"unknown detection {detection_id!r}"
                )
            if detection.verdict != "attack":
                self._reject_locked("detection-not-attack")
                raise BadMitigationError(
                    f"detection {detection_id!r} verdict is "
                    f"{detection.verdict!r}, not 'attack'"
                )
            if target_id in self._mitigations:
                self._reject_locked("already-mitigated")
                raise ActiveMitigationError(
                    f"target {target_id!r} already mitigated; stand down first"
                )
            self._mit_seq += 1
            mitigation_id = f"mit-{self._mit_seq}"
            record = MitigationRecord(
                mitigation_id=mitigation_id,
                target_id=target_id,
                detection_id=detection_id,
                level=level,
                status="active",
                seq=seq,
                digest=_pin(
                    "mitigate", mitigation_id, target_id, detection_id,
                    level, "active", seq,
                ),
            )
            self._mitigations[target_id] = record
            self._audit_locked(
                KIND_MITIGATED,
                {
                    "mitigation_id": mitigation_id,
                    "target_id": target_id,
                    "detection_id": detection_id,
                    "level": level,
                    "digest": record.digest,
                },
            )
            return record

    def stand_down(
        self, target_id: str, seq: int, reason: str
    ) -> StandDownRecord:
        """End the active mitigation for a target."""
        _check_seq(seq, "seq")
        target_id = _check_nonempty_str(target_id, "target_id")
        reason = _check_nonempty_str(reason, "reason")
        self._claim_seq(seq)
        with self._lock:
            record = self._mitigations.get(target_id)
            if record is None:
                self._reject_locked("no-active-mitigation")
                raise UnknownMitigationError(
                    f"no active mitigation for {target_id!r}"
                )
            del self._mitigations[target_id]
            self._past_mitigations.append(record)
            stand_down = StandDownRecord(
                target_id=target_id,
                mitigation_id=record.mitigation_id,
                reason=reason,
                seq=seq,
                digest=_pin(
                    "stand-down", target_id, record.mitigation_id, reason,
                    seq,
                ),
            )
            self._stand_downs.append(stand_down)
            self._audit_locked(
                KIND_STOOD_DOWN,
                {
                    "target_id": target_id,
                    "mitigation_id": record.mitigation_id,
                },
            )
            return stand_down

    # -- allowlist ------------------------------------------------------

    def allowlist(
        self, entry_id: str, identity: str, seq: int, reason: str
    ) -> AllowlistRecord:
        """Pin a trusted-source bypass entry."""
        _check_seq(seq, "seq")
        entry_id = _check_nonempty_str(entry_id, "entry_id")
        identity = _check_nonempty_str(identity, "identity")
        reason = _check_nonempty_str(reason, "reason")
        self._claim_seq(seq)
        with self._lock:
            try:
                kind, value = _parse_identity(identity)
            except BadAllowlistError:
                self._reject_locked("bad-identity")
                raise
            if entry_id in self._allowlist:
                self._reject_locked("duplicate-allowlist")
                raise DuplicateAllowlistError(
                    f"allowlist entry {entry_id!r} already registered"
                )
            record = AllowlistRecord(
                entry_id=entry_id,
                identity=identity,
                reason=reason,
                seq=seq,
                active=True,
                digest=_pin(
                    "allowlist", entry_id, identity, reason, seq, True
                ),
            )
            self._allowlist[entry_id] = record
            self._allowlist_parsed[entry_id] = (kind, value)
            self._audit_locked(
                KIND_ALLOWLISTED,
                {"entry_id": entry_id, "digest": record.digest},
            )
            return record

    def remove_allowlist(
        self, entry_id: str, seq: int, reason: str
    ) -> AllowlistRecord:
        """Terminally remove an allowlist entry."""
        _check_seq(seq, "seq")
        entry_id = _check_nonempty_str(entry_id, "entry_id")
        reason = _check_nonempty_str(reason, "reason")
        self._claim_seq(seq)
        with self._lock:
            record = self._allowlist.get(entry_id)
            if record is None:
                self._reject_locked("unknown-allowlist")
                raise UnknownAllowlistError(
                    f"unknown allowlist entry {entry_id!r}"
                )
            if not record.active:
                self._reject_locked("allowlist-already-removed")
                raise UnknownAllowlistError(
                    f"allowlist entry {entry_id!r} already removed"
                )
            removed = AllowlistRecord(
                entry_id=record.entry_id,
                identity=record.identity,
                reason=reason,
                seq=seq,
                active=False,
                digest=_pin(
                    "allowlist", record.entry_id, record.identity, reason,
                    seq, False,
                ),
            )
            self._allowlist[entry_id] = removed
            del self._allowlist_parsed[entry_id]
            self._audit_locked(
                KIND_ALLOWLIST_REMOVED, {"entry_id": entry_id}
            )
            return removed

    # -- views ----------------------------------------------------------

    def profile(self, profile_id: str) -> ProfileRecord:
        with self._lock:
            record = self._profiles.get(
                _check_nonempty_str(profile_id, "profile_id")
            )
            if record is None:
                raise UnknownProfileError(f"unknown profile {profile_id!r}")
            return record

    def profile_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._profiles))

    def detection(self, detection_id: str) -> DetectionReport:
        with self._lock:
            report = self._detections.get(
                _check_nonempty_str(detection_id, "detection_id")
            )
            if report is None:
                raise UnknownDetectionError(
                    f"unknown detection {detection_id!r}"
                )
            return report

    def detection_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._detections))

    def active_mitigation(self, target_id: str) -> Optional[MitigationRecord]:
        with self._lock:
            return self._mitigations.get(
                _check_nonempty_str(target_id, "target_id")
            )

    def mitigated_targets(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._mitigations))

    def allowlist_entry(self, entry_id: str) -> AllowlistRecord:
        with self._lock:
            record = self._allowlist.get(
                _check_nonempty_str(entry_id, "entry_id")
            )
            if record is None:
                raise UnknownAllowlistError(
                    f"unknown allowlist entry {entry_id!r}"
                )
            return record

    def allowlist_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._allowlist))

    def active_allowlist_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(
                    entry_id
                    for entry_id, record in self._allowlist.items()
                    if record.active
                )
            )

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "profiles": len(self._profiles),
                "detections": len(self._detections),
                "active_mitigations": len(self._mitigations),
                "past_mitigations": len(self._past_mitigations),
                "allowlist_entries": len(self._allowlist),
                "active_allowlist": len(self._allowlist_parsed),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    ddos = DDoSProtection()
    profile = ddos.define_profile(
        "edge",
        ["volumetric-flood", "syn-flood", "slowloris", "amplification"],
        {
            "requests": (1000, 10000),
            "unique_sources": (500, 5000),
            "syn_ratio": (0.3, 0.7),
            "slow_connections": (100, 1000),
            "amplification_factor": (3.0, 10.0),
            "bandwidth_bytes": (10**9, 10**10),
            "error_rate": (0.1, 0.4),
        },
        1,
    )
    assert profile.verify()
    calm = ddos.detect(
        "ip:203.0.113.7",
        "edge",
        {
            "requests": 120,
            "unique_sources": 40,
            "syn_ratio": 0.05,
            "slow_connections": 5,
            "amplification_factor": 1.2,
            "bandwidth_bytes": 10**7,
            "error_rate": 0.01,
        },
        2,
    )
    assert calm.verdict == "normal" and calm.verify()
    flood = ddos.detect(
        "ip:198.51.100.9",
        "edge",
        {
            "requests": 50000,
            "unique_sources": 20000,
            "syn_ratio": 0.02,
            "slow_connections": 10,
            "amplification_factor": 1.1,
            "bandwidth_bytes": 5 * 10**10,
            "error_rate": 0.02,
        },
        3,
    )
    assert flood.verdict == "attack"
    assert flood.attack_type == "volumetric-flood"
    assert flood.verify()
    mit = ddos.mitigate("edge-pop-1", flood.detection_id, "scrub", 4)
    assert mit.verify() and ddos.active_mitigation("edge-pop-1") is not None
    ddos.stand_down("edge-pop-1", 5, "traffic normalized")
    assert ddos.active_mitigation("edge-pop-1") is None
    entry = ddos.allowlist("ops", "cidr:203.0.113.0/24", 6, "ops netblock")
    assert entry.verify()
    bypassed = ddos.detect(
        "ip:203.0.113.7",
        "edge",
        {
            "requests": 999999,
            "unique_sources": 999999,
            "syn_ratio": 0.99,
            "slow_connections": 999999,
            "amplification_factor": 99.0,
            "bandwidth_bytes": 10**12,
            "error_rate": 0.99,
        },
        7,
    )
    assert bypassed.allowlisted and bypassed.verdict == "normal"
    print("ddos-protection OK: profile, detect, mitigate, allowlist")
    return None


if __name__ == "__main__":
    main()
