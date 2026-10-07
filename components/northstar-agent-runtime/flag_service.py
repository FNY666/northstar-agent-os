"""LaunchDarkly-style feature flag service: targeting, rules, percentage rollouts.

Where ``feature_flags.py`` is the small gate bookkeeper, ``FlagService`` is the
*operator* interface: a named-flag registry with per-subject targeting rules,
percentage rollouts over deterministic hash buckets, and a master kill
switch. ``create()`` defines a flag, ``evaluate(key, subject_id, seq)`` resolves
a stable ``EvaluationReport`` for a subject, and ``rollout(key, percentage,
seq)`` moves the rollout dial. Host-supplied targeting rules are pinned as
frozen ``RuleRecord`` digests so the rule set that produced a verdict is
auditable.

Evaluation precedence (first match wins):
  1. Flag disabled (kill switch) -> ``default`` variation.
  2. A targeting rule whose attribute predicate matches the subject -> that
     rule's variation.
  3. Percentage rollout -> hashed into 10_000 buckets; ``bucket < pct*100``
     takes the ``on`` variation, otherwise the ``off`` variation.
  4. No rule, no rollout -> ``default`` variation.

The same ``(flag.key, subject_id)`` pair always yields the same verdict --
stable across restarts, no randomness, no wall-clock. Caller-supplied int
seqs sequence every mutation; attribute predicates compare only host-supplied
attribute values, so a lying host gets a consistent rollout of lies (same
GIGO boundary as the rest of the batch line).

House style: frozen dataclasses, fail-closed validation (``TypeError`` on
wrong types -- bool is not a number, ``ValueError`` on bad values),
stdlib-only, version/schema pins, ``main()`` self-check. No wall-clock.

Honest scope: rollout gating answers "is this subject in the cohort", never
"may this action run" -- gates still decide. A percentage rollout is not
randomization; hostile subjects can compute their own bucket. Rules evaluate
host-reported attributes and cannot prove anything about the real subject.

Version pin: flag-service.v1
Schema pin: northstar.flag-service.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

FLAG_SERVICE_VERSION = "flag-service.v1"
SCHEMA_PIN = "northstar.flag-service.v1"

#: Hash buckets per flag; rollout_pct * 100 of them are "on".
BUCKETS = 10_000

_HASH_DOMAIN = "northstar.flag-service.v1"

_ON_VARIATION = "on"
_OFF_VARIATION = "off"


class FlagServiceError(Exception):
    """Base error for the flag service."""


class DuplicateFlagError(FlagServiceError):
    """A flag key is already registered."""


class UnknownFlagError(FlagServiceError):
    """The named flag does not exist."""


class DuplicateRuleError(FlagServiceError):
    """The flag already has this rule id."""


class UnknownRuleError(FlagServiceError):
    """The named rule does not exist on the flag."""


def _check_str(name: str, value: object, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise ValueError(f"{name} must be non-empty")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain NUL")
    return value


def _check_bool(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a bool, got {type(value).__name__}")
    return value


def _check_seq(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"seq must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError("seq must be >= 0")
    return value


def _check_pct(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number, got {type(value).__name__}")
    pct = float(value)
    if not (pct == pct) or pct in (float("inf"), float("-inf")):
        raise ValueError(f"{name} must be finite")
    if not 0.0 <= pct <= 100.0:
        raise ValueError(f"{name} must be in [0, 100]")
    return pct


def _digest(*parts: bytes) -> str:
    h = hashlib.sha256(_HASH_DOMAIN.encode())
    for p in parts:
        h.update(b"\x00" + p)
    return "sha256:" + h.hexdigest()


def _bucket(flag_key: str, subject_id: str) -> int:
    digest = hashlib.sha256(
        _HASH_DOMAIN.encode() + b"\x01" + flag_key.encode() + b"\x02" + subject_id.encode()
    ).digest()
    return int.from_bytes(digest[:8], "big") % BUCKETS


def _check_predicate(predicate: object) -> Mapping[str, Any]:
    if not isinstance(predicate, Mapping):
        raise TypeError(f"predicate must be a mapping, got {type(predicate).__name__}")
    if not predicate:
        raise ValueError("predicate must be non-empty")
    for k, v in predicate.items():
        if not isinstance(k, str) or not k:
            raise TypeError("predicate keys must be non-empty str")
        if isinstance(v, bool) or isinstance(v, (int, float, str)):
            pass
        else:
            raise TypeError(f"predicate value for {k!r} must be bool/int/float/str")
    return predicate


def _canonical_attrs(attrs: Mapping[str, Any]) -> Tuple[Tuple[str, Any], ...]:
    return tuple(sorted(attrs.items()))


@dataclass(frozen=True)
class RuleRecord:
    """A frozen targeting rule: attribute predicate -> variation."""

    rule_id: str
    predicate: Tuple[Tuple[str, Any], ...]
    variation: Any
    created_seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "predicate": list(self.predicate),
            "variation": self.variation,
            "created_seq": self.created_seq,
            "digest": self.digest,
            "version": FLAG_SERVICE_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class FlagRecord:
    """A frozen snapshot of a flag's configuration."""

    key: str
    description: str
    default_variation: Any
    enabled: bool
    rollout_pct: float
    rules: Tuple[RuleRecord, ...]
    created_seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "description": self.description,
            "default_variation": self.default_variation,
            "enabled": self.enabled,
            "rollout_pct": self.rollout_pct,
            "rules": [r.as_dict() for r in self.rules],
            "created_seq": self.created_seq,
            "digest": self.digest,
            "version": FLAG_SERVICE_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class EvaluationReport:
    """The frozen verdict of evaluating one flag for one subject."""

    flag_key: str
    subject_id: str
    variation: Any
    reason: str  # "disabled" | "rule" | "rollout" | "default"
    rule_id: Optional[str]
    bucket: Optional[int]
    flag_digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "flag_key": self.flag_key,
            "subject_id": self.subject_id,
            "variation": self.variation,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "bucket": self.bucket,
            "flag_digest": self.flag_digest,
            "seq": self.seq,
            "version": FLAG_SERVICE_VERSION,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class RolloutRecord:
    """A frozen record of a rollout dial change."""

    flag_key: str
    old_pct: float
    new_pct: float
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "flag_key": self.flag_key,
            "old_pct": self.old_pct,
            "new_pct": self.new_pct,
            "seq": self.seq,
            "digest": self.digest,
            "version": FLAG_SERVICE_VERSION,
            "schema": SCHEMA_PIN,
        }


class FlagService:
    """RLock-guarded registry of feature flags."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._flags: Dict[str, "_MutableFlag"] = {}

    # ---- internal -----------------------------------------------------
    def _get(self, key: str) -> "_MutableFlag":
        flag = self._flags.get(key)
        if flag is None:
            raise UnknownFlagError(f"unknown flag {key!r}")
        return flag

    # ---- management ---------------------------------------------------
    def create(self, key: str, seq: int, description: str = "",
               default_variation: Any = False) -> FlagRecord:
        """Register a new flag, enabled, with no rollout and no rules."""
        _check_str("key", key)
        _check_seq(seq)
        _check_str("description", description, allow_empty=True)
        if isinstance(default_variation, float) and (
            default_variation != default_variation
            or default_variation in (float("inf"), float("-inf"))
        ):
            raise ValueError("default_variation must be finite")
        with self._lock:
            if key in self._flags:
                raise DuplicateFlagError(f"flag {key!r} already registered")
            flag = _MutableFlag(
                key=key,
                description=description,
                default_variation=default_variation,
                enabled=True,
                rollout_pct=0.0,
                rules=[],
                created_seq=seq,
            )
            self._flags[key] = flag
            return flag.snapshot()

    def remove(self, key: str, seq: int) -> None:
        """Remove a flag and all its rules."""
        _check_str("key", key)
        _check_seq(seq)
        with self._lock:
            self._get(key)
            del self._flags[key]

    def enable(self, key: str, seq: int) -> FlagRecord:
        _check_str("key", key)
        _check_seq(seq)
        with self._lock:
            flag = self._get(key)
            flag.enabled = True
            return flag.snapshot()

    def disable(self, key: str, seq: int) -> FlagRecord:
        """Kill switch: evaluation always returns the default variation."""
        _check_str("key", key)
        _check_seq(seq)
        with self._lock:
            flag = self._get(key)
            flag.enabled = False
            return flag.snapshot()

    def add_rule(self, key: str, rule_id: str, predicate: Mapping[str, Any],
                 variation: Any, seq: int) -> RuleRecord:
        """Append a targeting rule evaluated before the rollout dial."""
        _check_str("key", key)
        _check_str("rule_id", rule_id)
        pred = _check_predicate(predicate)
        _check_seq(seq)
        with self._lock:
            flag = self._get(key)
            if any(r.rule_id == rule_id for r in flag.rules):
                raise DuplicateRuleError(f"rule {rule_id!r} already on flag {key!r}")
            canonical = _canonical_attrs(dict(pred))
            digest = _digest(
                b"rule", key.encode(), rule_id.encode(),
                repr(canonical).encode(), repr(variation).encode(),
                str(seq).encode(),
            )
            rule = RuleRecord(
                rule_id=rule_id,
                predicate=canonical,
                variation=variation,
                created_seq=seq,
                digest=digest,
            )
            flag.rules.append(rule)
            return rule

    def remove_rule(self, key: str, rule_id: str, seq: int) -> None:
        _check_str("key", key)
        _check_str("rule_id", rule_id)
        _check_seq(seq)
        with self._lock:
            flag = self._get(key)
            for i, r in enumerate(flag.rules):
                if r.rule_id == rule_id:
                    del flag.rules[i]
                    return
            raise UnknownRuleError(f"unknown rule {rule_id!r} on flag {key!r}")

    def rollout(self, key: str, percentage: float, seq: int) -> RolloutRecord:
        """Set the percentage dial; 100 = every subject gets the on variation."""
        _check_str("key", key)
        pct = _check_pct("percentage", percentage)
        _check_seq(seq)
        with self._lock:
            flag = self._get(key)
            old = flag.rollout_pct
            flag.rollout_pct = pct
            digest = _digest(
                b"rollout", key.encode(), repr(old).encode(),
                repr(pct).encode(), str(seq).encode(),
            )
            return RolloutRecord(
                flag_key=key, old_pct=old, new_pct=pct, seq=seq, digest=digest
            )

    # ---- evaluation ---------------------------------------------------
    def evaluate(self, key: str, subject_id: str, seq: int,
                 attributes: Optional[Mapping[str, Any]] = None) -> EvaluationReport:
        """Resolve the variation for a subject (stable, deterministic)."""
        _check_str("key", key)
        _check_str("subject_id", subject_id)
        _check_seq(seq)
        if attributes is None:
            attrs: Dict[str, Any] = {}
        elif isinstance(attributes, Mapping):
            attrs = dict(attributes)
        else:
            raise TypeError("attributes must be a mapping or None")
        with self._lock:
            flag = self._get(key)
            snapshot = flag.snapshot()
            rules = list(flag.rules)
            enabled = flag.enabled
            pct = flag.rollout_pct
            default = flag.default_variation

        def _report(variation: Any, reason: str,
                    rule_id: Optional[str], bucket: Optional[int]) -> EvaluationReport:
            return EvaluationReport(
                flag_key=key, subject_id=subject_id, variation=variation,
                reason=reason, rule_id=rule_id, bucket=bucket,
                flag_digest=snapshot.digest, seq=seq,
            )

        if not enabled:
            return _report(default, "disabled", None, None)
        for rule in rules:
            if all(attrs.get(k) == v for k, v in rule.predicate):
                return _report(rule.variation, "rule", rule.rule_id, None)
        if pct > 0.0:
            bkt = _bucket(key, subject_id)
            if bkt < pct * 100:
                return _report(_ON_VARIATION, "rollout", None, bkt)
            return _report(_OFF_VARIATION, "rollout", None, bkt)
        return _report(default, "default", None, None)

    # ---- views --------------------------------------------------------
    def keys(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._flags))

    def flag(self, key: str) -> FlagRecord:
        _check_str("key", key)
        with self._lock:
            return self._get(key).snapshot()


@dataclass
class _MutableFlag:
    key: str
    description: str
    default_variation: Any
    enabled: bool
    rollout_pct: float
    rules: List[RuleRecord]
    created_seq: int

    def snapshot(self) -> FlagRecord:
        rules = tuple(self.rules)
        digest = _digest(
            b"flag", self.key.encode(), self.description.encode(),
            repr(self.default_variation).encode(),
            b"1" if self.enabled else b"0",
            repr(self.rollout_pct).encode(),
            repr(tuple(r.digest for r in rules)).encode(),
            str(self.created_seq).encode(),
        )
        return FlagRecord(
            key=self.key,
            description=self.description,
            default_variation=self.default_variation,
            enabled=self.enabled,
            rollout_pct=self.rollout_pct,
            rules=rules,
            created_seq=self.created_seq,
            digest=digest,
        )


def flag_service_audit_event(kind: str, seq: int, **fields: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for a flag-service event."""
    allowed = {
        "created", "removed", "enabled", "disabled", "rule-added",
        "rule-removed", "rolled-out", "rejected",
    }
    if kind not in allowed:
        raise FlagServiceError(
            f"unknown audit kind {kind!r}; allowed: {sorted(allowed)}"
        )
    _check_seq(seq)
    record = {
        "schema": "audit.ndjson/1",
        "kind": f"flag-service.{kind}",
        "module": FLAG_SERVICE_VERSION,
        "seq": seq,
    }
    record.update(fields)
    return record


def main() -> None:
    svc = FlagService()
    rec = svc.create("dark-mode", seq=1, description="new theme")
    assert rec.digest.startswith("sha256:"), rec
    try:
        svc.create("dark-mode", seq=2)
    except DuplicateFlagError:
        pass
    else:
        raise AssertionError("duplicate create should fail")
    # no rollout yet: default False
    rep = svc.evaluate("dark-mode", "alice", seq=3)
    assert rep.variation is False and rep.reason == "default", rep
    # targeting rule wins over rollout
    svc.add_rule("dark-mode", "staff", {"email": "a@co"}, "staff-on", seq=4)
    rep = svc.evaluate("dark-mode", "alice", seq=5, attributes={"email": "a@co"})
    assert rep.variation == "staff-on" and rep.reason == "rule", rep
    rep = svc.evaluate("dark-mode", "alice", seq=6)
    assert rep.variation is False and rep.reason == "default", rep
    # 100% rollout -> everyone gets "on"
    svc.rollout("dark-mode", 100.0, seq=7)
    rep = svc.evaluate("dark-mode", "bob", seq=8)
    assert rep.variation == "on" and rep.reason == "rollout", rep
    # deterministic across instances
    b1 = svc.evaluate("dark-mode", "carol", seq=9).bucket
    svc2 = FlagService()
    svc2.create("dark-mode", seq=1)
    svc2.rollout("dark-mode", 100.0, seq=2)
    b2 = svc2.evaluate("dark-mode", "carol", seq=3).bucket
    assert b1 == b2, (b1, b2)
    # kill switch
    svc.disable("dark-mode", seq=10)
    rep = svc.evaluate("dark-mode", "bob", seq=11)
    assert rep.variation is False and rep.reason == "disabled", rep
    svc.enable("dark-mode", seq=12)
    svc.remove("dark-mode", seq=13)
    assert svc.keys() == (), svc.keys()
    try:
        svc.evaluate("dark-mode", "x", seq=14)
    except UnknownFlagError:
        pass
    else:
        raise AssertionError("evaluating removed flag should fail")
    print("flag-service OK: create, rules, rollout, kill-switch, refusals")


if __name__ == "__main__":
    main()
