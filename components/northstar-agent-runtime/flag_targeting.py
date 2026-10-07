"""Advanced feature-flag targeting: rule engine, staged gradual rollouts, multi-variation.

Research note: LaunchDarkly-style targeting with a JSON predicate AST (leaf
operators + ``and``/``or``/``not`` combinators), deterministic hash-bucket
rollouts over multiple named variations, and explicit *staged* rollout plans
(1% -> 10% -> 50% -> 100%) promoted by operator action, not by wall-clock.

Where ``flag_service.py`` is the simple on/off gate bookkeeper (flat
equality predicates, single percentage dial), ``FlagTargeting`` is the
targeting *policy* engine:

* ``define()`` registers a flag with a named-variation set and a default.
* ``add_rule()`` pins a targeting rule: a predicate AST over host-reported
  subject attributes, a target variation, and a priority. First matching
  rule (lowest priority value) wins.
* ``rollout()`` installs a staged rollout plan; ``promote()`` advances the
  current stage by explicit, seq-gated operator action.
* ``evaluate()`` resolves a stable ``EvaluationReport`` for a subject:
  kill switch -> rule match -> current stage weights -> default.

Predicate AST (host-reported attributes; fail-closed ``False`` on type
mismatch, never raised at evaluation time):

    {"attr": "country", "op": "eq", "value": "DE"}
    {"attr": "version", "op": "semver-gt", "value": "2.1.0"}
    {"all": [{"attr": "tier", "op": "in", "value": ["pro", "team"]},
             {"not": {"attr": "internal", "op": "eq", "value": True}}]}

Leaf operators (pinned vocabulary): eq, ne, in, not-in, gt, gte, lt, lte,
starts-with, ends-with, contains, semver-eq, semver-gt, semver-lt.
Combinators: all, any, not. Comparison operators require numeric (int/float,
never bool) operands on both sides; string operators require strings.

Rollout math: each subject lands in a stable bucket ``0..9999`` derived
from ``sha256(domain || flag || subject)``. In stage ``s`` with ``percent``
``p``, buckets ``< p*100`` are *in* the rollout; the in-rollout bucket
selects a variation by the stage's weight table (weights sum to 100).
``promote()`` is the only way the stage index moves -- no wall-clock.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs on every mutation (bool/negative/rewind refused; failed mutations
consume their seq), RLock-guarded, fail-closed error taxonomy, stdlib-only,
``sha256:`` digest pins re-derivable via ``verify()``, ``audit.ndjson/1``
records on mutations (ids + digests only), version/schema pins,
``main()`` self-check. No wall-clock.

Honest scope: targeting answers "which cohort does this subject report
into", never "may this action run" -- gates still decide. Predicates
evaluate host-reported attributes and cannot prove anything about the real
subject; bucket membership is public to anyone who knows the flag key and
subject id, so rollouts are *not* an access-control boundary. A staged
rollout is a risk-dial, not randomization.

Version pin: flag-targeting.v1
Schema pin: northstar.flag-targeting.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

FLAG_TARGETING_VERSION = "flag-targeting.v1"
SCHEMA_PIN = "northstar.flag-targeting.v1"

#: Hash buckets per flag; stage.percent * 100 of them are in the rollout.
BUCKETS = 10_000

_HASH_DOMAIN = "northstar.flag-targeting.v1"

_LEAF_OPS = frozenset({
    "eq", "ne", "in", "not-in",
    "gt", "gte", "lt", "lte",
    "starts-with", "ends-with", "contains",
    "semver-eq", "semver-gt", "semver-lt",
})
_COMBINATORS = frozenset({"all", "any", "not"})
_AUDIT_KINDS = frozenset({
    "flag-defined", "rule-added", "rule-removed", "rollout-set",
    "promoted", "enabled", "disabled", "rejected",
})


class FlagTargetingError(Exception):
    """Base error for flag targeting."""


class DuplicateFlagError(FlagTargetingError):
    """A flag key is already defined."""


class UnknownFlagError(FlagTargetingError):
    """The named flag does not exist."""


class DuplicateRuleError(FlagTargetingError):
    """The flag already has a rule with this id."""


class UnknownRuleError(FlagTargetingError):
    """The named rule does not exist on the flag."""


class BadPredicateError(FlagTargetingError):
    """The predicate AST is malformed."""


class BadVariationError(FlagTargetingError):
    """The variation set / weights are malformed."""


class BadStageError(FlagTargetingError):
    """The rollout stage plan is malformed."""


class SeqOrderError(FlagTargetingError):
    """A mutation seq was not strictly increasing."""


def _check_str(name: str, value: object, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise ValueError(f"{name} must be non-empty")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain NUL")
    return value


def _check_seq(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"seq must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError("seq must be >= 0")
    return value


def _digest(*parts: bytes) -> str:
    h = hashlib.sha256(_HASH_DOMAIN.encode())
    for p in parts:
        h.update(b"\x00" + p)
    return "sha256:" + h.hexdigest()


def _bucket(flag_key: str, subject_id: str) -> int:
    digest = hashlib.sha256(
        _HASH_DOMAIN.encode()
        + b"\x01"
        + flag_key.encode()
        + b"\x02"
        + subject_id.encode()
    ).digest()
    return int.from_bytes(digest[:8], "big") % BUCKETS


def _canonical(value: object) -> bytes:
    """Deterministic byte encoding for digest pins (JCS-shaped, stdlib-only)."""
    if value is None:
        return b"n"
    if isinstance(value, bool):
        return b"b1" if value else b"b0"
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise ValueError("integers |n| >= 2**53 refused")
        return b"i" + str(value).encode()
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite floats refused")
        return b"f" + repr(value).encode()
    if isinstance(value, str):
        return b"s" + value.encode()
    if isinstance(value, (list, tuple)):
        return b"[" + b",".join(_canonical(v) for v in value) + b"]"
    if isinstance(value, dict):
        items = sorted((str(k), v) for k, v in value.items())
        return b"{" + b",".join(_canonical(k) + b":" + _canonical(v) for k, v in items) + b"}"
    raise TypeError(f"cannot canonicalize {type(value).__name__}")


# ---------------------------------------------------------------------------
# Predicate AST
# ---------------------------------------------------------------------------

def _check_semver(value: object) -> Tuple[int, int, int]:
    if not isinstance(value, str):
        raise BadPredicateError(f"semver value must be a str, got {type(value).__name__}")
    parts = value.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise BadPredicateError(f"semver value {value!r} must be X.Y.Z numeric")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def _check_predicate(predicate: object) -> Mapping[str, Any]:
    """Validate the predicate AST fail-closed at rule-add time."""
    if not isinstance(predicate, Mapping):
        raise BadPredicateError(
            f"predicate must be a mapping, got {type(predicate).__name__}"
        )
    if set(predicate.keys()) == {"attr", "op", "value"}:
        attr = predicate["attr"]
        op = predicate["op"]
        _check_str("attr", attr)
        _check_str("op", op)
        if op not in _LEAF_OPS:
            raise BadPredicateError(f"unknown leaf op {op!r}; allowed: {sorted(_LEAF_OPS)}")
        val = predicate["value"]
        if op in ("in", "not-in"):
            if not isinstance(val, (list, tuple)) or not val:
                raise BadPredicateError("in/not-in value must be a non-empty list")
            for item in val:
                if isinstance(item, bool) or not isinstance(item, (int, float, str)):
                    raise BadPredicateError("in/not-in items must be int/float/str")
        elif op.startswith("semver-"):
            _check_semver(val)
        elif op in ("eq", "ne"):
            if not isinstance(val, (bool, int, float, str)):
                raise BadPredicateError("eq/ne value must be bool/int/float/str")
        elif op in ("gt", "gte", "lt", "lte"):
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise BadPredicateError("comparison value must be a number")
        else:  # string operators
            _check_str("value", val)
        return predicate
    if set(predicate.keys()) == {"all"} or set(predicate.keys()) == {"any"}:
        key = "all" if "all" in predicate else "any"
        children = predicate[key]
        if not isinstance(children, (list, tuple)) or not children:
            raise BadPredicateError(f"{key} must be a non-empty list of predicates")
        for child in children:
            _check_predicate(child)
        return predicate
    if set(predicate.keys()) == {"not"}:
        _check_predicate(predicate["not"])
        return predicate
    raise BadPredicateError(
        "predicate must be a leaf {attr, op, value}, {all: [...]}, "
        f"{{any: [...]}}, or {{not: ...}}; got keys {sorted(map(str, predicate.keys()))}"
    )


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _eval_leaf(attr_value: Any, op: str, expected: Any) -> bool:
    if op == "eq":
        return type(attr_value) is type(expected) and attr_value == expected
    if op == "ne":
        return not (type(attr_value) is type(expected) and attr_value == expected)
    if op == "in":
        return any(type(attr_value) is type(i) and attr_value == i for i in expected)
    if op == "not-in":
        return not any(type(attr_value) is type(i) and attr_value == i for i in expected)
    if op in ("gt", "gte", "lt", "lte"):
        if not (_is_number(attr_value) and _is_number(expected)):
            return False
        if op == "gt":
            return attr_value > expected
        if op == "gte":
            return attr_value >= expected
        if op == "lt":
            return attr_value < expected
        return attr_value <= expected
    if op in ("starts-with", "ends-with", "contains"):
        if not (isinstance(attr_value, str) and isinstance(expected, str)):
            return False
        if op == "starts-with":
            return attr_value.startswith(expected)
        if op == "ends-with":
            return attr_value.endswith(expected)
        return expected in attr_value
    if op.startswith("semver-"):
        if not isinstance(attr_value, str):
            return False
        try:
            have = _check_semver(attr_value)
        except BadPredicateError:
            return False
        want = _check_semver(expected)
        if op == "semver-eq":
            return have == want
        if op == "semver-gt":
            return have > want
        return have < want
    return False  # unreachable: ops validated at add time


def _eval_predicate(predicate: Mapping[str, Any], attributes: Mapping[str, Any]) -> bool:
    if "all" in predicate:
        return all(_eval_predicate(c, attributes) for c in predicate["all"])
    if "any" in predicate:
        return any(_eval_predicate(c, attributes) for c in predicate["any"])
    if "not" in predicate:
        return not _eval_predicate(predicate["not"], attributes)
    attr_value = attributes.get(predicate["attr"], None)
    if attr_value is None:
        return False
    return _eval_leaf(attr_value, predicate["op"], predicate["value"])


# ---------------------------------------------------------------------------
# Variations and stages
# ---------------------------------------------------------------------------

def _check_variations(variations: object) -> List[str]:
    if not isinstance(variations, (list, tuple)) or len(variations) < 2:
        raise BadVariationError("variations must be a list of at least 2 names")
    names: List[str] = []
    for v in variations:
        _check_str("variation", v)
        if v in names:
            raise BadVariationError(f"duplicate variation {v!r}")
        names.append(v)
    return names


def _check_weights(weights: object, variations: List[str]) -> Dict[str, float]:
    if not isinstance(weights, Mapping):
        raise BadVariationError("weights must be a mapping variation -> pct")
    if set(weights.keys()) != set(variations):
        raise BadVariationError("weights must cover exactly the flag variations")
    total = 0.0
    out: Dict[str, float] = {}
    for v in variations:
        w = weights[v]
        if isinstance(w, bool) or not isinstance(w, (int, float)):
            raise TypeError(f"weight for {v!r} must be a number")
        w = float(w)
        if w != w or w in (float("inf"), float("-inf")):
            raise ValueError(f"weight for {v!r} must be finite")
        if w < 0:
            raise ValueError(f"weight for {v!r} must be >= 0")
        out[v] = w
        total += w
    if abs(total - 100.0) > 1e-9:
        raise BadVariationError(f"weights must sum to 100, got {total}")
    return out


def _check_stage(stage: object, variations: List[str]) -> Dict[str, Any]:
    if not isinstance(stage, Mapping):
        raise BadStageError("stage must be a mapping")
    pct = stage.get("percent")
    if isinstance(pct, bool) or not isinstance(pct, (int, float)):
        raise BadStageError("stage percent must be a number")
    pct = float(pct)
    if not (0.0 <= pct <= 100.0) or pct != pct:
        raise BadStageError("stage percent must be finite and in [0, 100]")
    weights = stage.get("weights")
    if weights is None:
        # Default: all traffic to the first variation.
        weights = {variations[0]: 100.0, **{v: 0.0 for v in variations[1:]}}
    weights = _check_weights(weights, variations)
    return {"percent": pct, "weights": weights}


def _pick_variation(bucket: int, weights: Dict[str, float], order: List[str]) -> str:
    """Deterministically map a bucket to a variation by weight ranges."""
    point = (bucket % 10000) / 100.0  # 0.00 .. 99.99
    cursor = 0.0
    for v in order:
        cursor += weights[v]
        if point < cursor or v == order[-1]:
            return v
    return order[-1]


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleRecord:
    rule_id: str
    predicate: Mapping[str, Any]
    variation: str
    priority: int
    description: str
    added_seq: int
    digest: str

    def verify(self, flag_key: str) -> bool:
        return self.digest == _digest(
            _HASH_DOMAIN.encode(), flag_key.encode(),
            self.rule_id.encode(),
            _canonical(dict(self.predicate)),
            self.variation.encode(),
            _canonical(self.priority),
            self.description.encode(),
            _canonical(self.added_seq),
        )


@dataclass(frozen=True)
class FlagRecord:
    key: str
    description: str
    variations: Tuple[str, ...]
    default_variation: str
    enabled: bool
    created_seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            _HASH_DOMAIN.encode(), self.key.encode(),
            self.description.encode(),
            _canonical(list(self.variations)),
            self.default_variation.encode(),
            _canonical(self.created_seq),
        )


@dataclass(frozen=True)
class StageReport:
    key: str
    stage_index: int
    percent: float
    weights: Mapping[str, float]
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            _HASH_DOMAIN.encode(), self.key.encode(),
            _canonical(self.stage_index), _canonical(self.percent),
            _canonical(dict(self.weights)), _canonical(self.seq),
        )


@dataclass(frozen=True)
class EvaluationReport:
    key: str
    subject_id: str
    variation: str
    reason: str  # "rule" | "rollout" | "default"
    rule_id: Optional[str]
    bucket: int
    stage_index: Optional[int]
    digest: str

    def verify(self, variations: List[str]) -> bool:
        return self.digest == _digest(
            _HASH_DOMAIN.encode(), self.key.encode(),
            self.subject_id.encode(), self.variation.encode(),
            self.reason.encode(),
            (self.rule_id or "").encode(),
            _canonical(self.bucket),
            _canonical(-1 if self.stage_index is None else self.stage_index),
        )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class FlagTargeting:
    """Targeting-rule engine with staged gradual rollouts.

    Thread-safe via a single RLock. Every mutating call takes a
    strictly-increasing caller ``seq`` (per flag); failed mutations consume
    their seq (fail-closed ledger position). Evaluation is a pure read view:
    the seq is validated but not consumed.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._flags: Dict[str, FlagRecord] = {}
        self._rules: Dict[str, List[RuleRecord]] = {}
        self._plans: Dict[str, List[Dict[str, Any]]] = {}
        self._stage: Dict[str, int] = {}
        self._last_seq: Dict[str, int] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _mut_seq(self, key: str, seq: int) -> None:
        """Validate and consume a mutation seq (failed mutations consume it)."""
        seq = _check_seq(seq)
        last = self._last_seq.get(key, -1)
        self._last_seq[key] = seq  # consume first, fail-closed
        if seq <= last:
            raise SeqOrderError(
                f"seq {seq} must be strictly greater than last seq {last} for {key!r}"
            )

    def _get(self, key: str) -> FlagRecord:
        try:
            return self._flags[key]
        except KeyError:
            raise UnknownFlagError(f"unknown flag {key!r}") from None

    def _emit(self, kind: str, seq: int, **fields: Any) -> None:
        self._audit.append(flag_targeting_audit_event(kind, seq, **fields))

    # -- flag lifecycle -------------------------------------------------

    def define(
        self,
        key: str,
        variations: List[str],
        seq: int,
        default: Optional[str] = None,
        description: str = "",
    ) -> FlagRecord:
        """Register a flag with a named-variation set."""
        _check_str("key", key)
        names = _check_variations(variations)
        _check_seq(seq)
        default = default if default is not None else names[0]
        _check_str("default", default)
        if default not in names:
            raise BadVariationError(f"default {default!r} not in variations")
        _check_str("description", description, allow_empty=True)
        with self._lock:
            if key in self._flags:
                raise DuplicateFlagError(f"flag {key!r} already defined")
            self._mut_seq(key, seq)
            digest = _digest(
                _HASH_DOMAIN.encode(), key.encode(),
                description.encode(),
                _canonical(names), default.encode(), _canonical(seq),
            )
            rec = FlagRecord(
                key=key, description=description,
                variations=tuple(names), default_variation=default,
                enabled=True, created_seq=seq, digest=digest,
            )
            self._flags[key] = rec
            self._rules[key] = []
            self._plans[key] = []
            self._stage[key] = 0
            self._emit("flag-defined", seq, key=key, digest=digest)
            return rec

    def enable(self, key: str, seq: int) -> FlagRecord:
        return self._set_enabled(key, seq, True)

    def disable(self, key: str, seq: int) -> FlagRecord:
        """Kill switch: disabled flags evaluate to the default variation."""
        return self._set_enabled(key, seq, False)

    def _set_enabled(self, key: str, seq: int, enabled: bool) -> FlagRecord:
        _check_str("key", key)
        _check_seq(seq)
        with self._lock:
            rec = self._get(key)
            self._mut_seq(key, seq)
            new = FlagRecord(
                key=rec.key, description=rec.description,
                variations=rec.variations, default_variation=rec.default_variation,
                enabled=enabled, created_seq=rec.created_seq,
                digest=_digest(
                    _HASH_DOMAIN.encode(), rec.key.encode(),
                    rec.description.encode(),
                    _canonical(list(rec.variations)),
                    rec.default_variation.encode(),
                    _canonical(rec.created_seq),
                ),
            )
            self._flags[key] = new
            self._emit("enabled" if enabled else "disabled", seq, key=key)
            return new

    # -- rules ----------------------------------------------------------

    def add_rule(
        self,
        key: str,
        rule_id: str,
        predicate: Mapping[str, Any],
        variation: str,
        seq: int,
        priority: int = 0,
        description: str = "",
    ) -> RuleRecord:
        """Pin a targeting rule; lowest priority value wins on match."""
        _check_str("key", key)
        _check_str("rule_id", rule_id)
        predicate = _check_predicate(predicate)
        _check_str("variation", variation)
        _check_seq(seq)
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise TypeError("priority must be an int")
        _check_str("description", description, allow_empty=True)
        with self._lock:
            rec = self._get(key)
            if variation not in rec.variations:
                raise BadVariationError(
                    f"variation {variation!r} not in flag variations"
                )
            if any(r.rule_id == rule_id for r in self._rules[key]):
                raise DuplicateRuleError(
                    f"rule {rule_id!r} already exists on flag {key!r}"
                )
            self._mut_seq(key, seq)
            digest = _digest(
                _HASH_DOMAIN.encode(), key.encode(), rule_id.encode(),
                _canonical(dict(predicate)), variation.encode(),
                _canonical(priority), description.encode(), _canonical(seq),
            )
            rule = RuleRecord(
                rule_id=rule_id, predicate=predicate, variation=variation,
                priority=priority, description=description,
                added_seq=seq, digest=digest,
            )
            self._rules[key].append(rule)
            self._rules[key].sort(key=lambda r: (r.priority, r.added_seq))
            self._emit(
                "rule-added", seq, key=key, rule_id=rule_id,
                variation=variation, digest=digest,
            )
            return rule

    def remove_rule(self, key: str, rule_id: str, seq: int) -> None:
        _check_str("key", key)
        _check_str("rule_id", rule_id)
        _check_seq(seq)
        with self._lock:
            self._get(key)
            for i, r in enumerate(self._rules[key]):
                if r.rule_id == rule_id:
                    self._mut_seq(key, seq)
                    del self._rules[key][i]
                    self._emit("rule-removed", seq, key=key, rule_id=rule_id)
                    return
            raise UnknownRuleError(f"rule {rule_id!r} not on flag {key!r}")

    # -- staged rollouts -------------------------------------------------

    def rollout(self, key: str, stages: List[Mapping[str, Any]], seq: int) -> List[Dict[str, Any]]:
        """Install a staged rollout plan; resets the current stage to 0."""
        _check_str("key", key)
        _check_seq(seq)
        if not isinstance(stages, (list, tuple)) or not stages:
            raise BadStageError("stages must be a non-empty list")
        with self._lock:
            rec = self._get(key)
            names = list(rec.variations)
            plan = [_check_stage(s, names) for s in stages]
            prev = None
            for s in plan:
                if prev is not None and s["percent"] < prev:
                    raise BadStageError("stage percents must be non-decreasing")
                prev = s["percent"]
            self._mut_seq(key, seq)
            self._plans[key] = plan
            self._stage[key] = 0
            digest = _digest(
                _HASH_DOMAIN.encode(), key.encode(),
                _canonical([
                    {"percent": s["percent"], "weights": s["weights"]}
                    for s in plan
                ]),
                _canonical(seq),
            )
            self._emit(
                "rollout-set", seq, key=key,
                stages=len(plan), digest=digest,
            )
            return [
                {"percent": s["percent"], "weights": dict(s["weights"])}
                for s in plan
            ]

    def promote(self, key: str, seq: int) -> StageReport:
        """Advance the rollout one stage (explicit operator action)."""
        _check_str("key", key)
        _check_seq(seq)
        with self._lock:
            rec = self._get(key)
            plan = self._plans[key]
            if not plan:
                raise BadStageError(f"flag {key!r} has no rollout plan")
            idx = self._stage[key]
            if idx + 1 >= len(plan):
                raise BadStageError(f"flag {key!r} already at final stage {idx}")
            self._mut_seq(key, seq)
            idx += 1
            self._stage[key] = idx
            stage = plan[idx]
            report = StageReport(
                key=key, stage_index=idx, percent=stage["percent"],
                weights=dict(stage["weights"]), seq=seq,
                digest=_digest(
                    _HASH_DOMAIN.encode(), key.encode(),
                    _canonical(idx), _canonical(stage["percent"]),
                    _canonical(dict(stage["weights"])), _canonical(seq),
                ),
            )
            self._emit(
                "promoted", seq, key=key, stage_index=idx,
                percent=stage["percent"], digest=report.digest,
            )
            return report

    # -- evaluation ------------------------------------------------------

    def evaluate(
        self,
        key: str,
        subject_id: str,
        attributes: Mapping[str, Any],
        seq: int,
    ) -> EvaluationReport:
        """Resolve the variation for a subject (pure read; seq not consumed)."""
        _check_str("key", key)
        _check_str("subject_id", subject_id)
        _check_seq(seq)  # validated, not consumed
        if not isinstance(attributes, Mapping):
            raise TypeError("attributes must be a mapping")
        with self._lock:
            rec = self._get(key)
            bucket = _bucket(key, subject_id)
            if not rec.enabled:
                return self._report(key, subject_id, rec.default_variation,
                                    "default", None, bucket, None)
            for rule in self._rules[key]:
                if _eval_predicate(rule.predicate, attributes):
                    return self._report(key, subject_id, rule.variation,
                                        "rule", rule.rule_id, bucket, None)
            plan = self._plans[key]
            if plan:
                idx = self._stage[key]
                stage = plan[idx]
                if bucket < stage["percent"] * 100:
                    var = _pick_variation(
                        bucket, stage["weights"], list(rec.variations))
                    return self._report(key, subject_id, var,
                                        "rollout", None, bucket, idx)
            return self._report(key, subject_id, rec.default_variation,
                                "default", None, bucket, None)

    def _report(self, key, subject_id, variation, reason, rule_id, bucket,
                stage_index) -> EvaluationReport:
        return EvaluationReport(
            key=key, subject_id=subject_id, variation=variation,
            reason=reason, rule_id=rule_id, bucket=bucket,
            stage_index=stage_index,
            digest=_digest(
                _HASH_DOMAIN.encode(), key.encode(), subject_id.encode(),
                variation.encode(), reason.encode(),
                (rule_id or "").encode(), _canonical(bucket),
                _canonical(-1 if stage_index is None else stage_index),
            ),
        )

    # -- views -----------------------------------------------------------

    def flag(self, key: str) -> FlagRecord:
        with self._lock:
            return self._get(key)

    def rules(self, key: str) -> List[RuleRecord]:
        with self._lock:
            self._get(key)
            return list(self._rules[key])

    def plan(self, key: str) -> List[Dict[str, Any]]:
        with self._lock:
            self._get(key)
            return [
                {"percent": s["percent"], "weights": dict(s["weights"])}
                for s in self._plans[key]
            ]

    def stage_index(self, key: str) -> int:
        with self._lock:
            self._get(key)
            return self._stage[key]

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit)


def flag_targeting_audit_event(kind: str, seq: int, **fields: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for a flag-targeting event.

    Only ids and digest pins cross the audit boundary -- predicate values
    and subject attributes never appear here.
    """
    if kind not in _AUDIT_KINDS:
        raise FlagTargetingError(
            f"unknown audit kind {kind!r}; allowed: {sorted(_AUDIT_KINDS)}"
        )
    _check_seq(seq)
    record = {
        "schema": "audit.ndjson/1",
        "kind": f"flag-targeting.{kind}",
        "module": FLAG_TARGETING_VERSION,
        "seq": seq,
    }
    record.update(fields)
    return record


def main() -> None:
    ft = FlagTargeting()
    rec = ft.define("new-ui", ["control", "treatment"], seq=1)
    assert rec.digest.startswith("sha256:"), rec
    assert rec.verify(), rec
    rule = ft.add_rule(
        "new-ui", "de-pro",
        {"all": [
            {"attr": "country", "op": "eq", "value": "DE"},
            {"attr": "tier", "op": "in", "value": ["pro", "team"]},
        ]},
        "treatment", seq=2, priority=0,
    )
    assert rule.verify("new-ui"), rule
    ft.rollout("new-ui", [{"percent": 10}, {"percent": 100}], seq=3)
    rep = ft.evaluate("new-ui", "u1", {"country": "DE", "tier": "pro"}, seq=4)
    assert rep.variation == "treatment" and rep.reason == "rule", rep
    assert rep.verify(["control", "treatment"]), rep
    # Deterministic: same subject, same verdict.
    again = ft.evaluate("new-ui", "u1", {"country": "DE", "tier": "pro"}, seq=5)
    assert again.variation == rep.variation and again.digest == rep.digest
    # Kill switch.
    ft.disable("new-ui", seq=6)
    rep2 = ft.evaluate("new-ui", "u1", {"country": "DE", "tier": "pro"}, seq=7)
    assert rep2.variation == "control" and rep2.reason == "default", rep2
    ft.enable("new-ui", seq=8)
    promo = ft.promote("new-ui", seq=9)
    assert promo.stage_index == 1 and promo.verify(), promo
    try:
        ft.define("new-ui", ["a", "b"], seq=10)
    except DuplicateFlagError:
        pass
    else:
        raise AssertionError("expected DuplicateFlagError")
    print("flag-targeting OK: define, rules, rollout, promote, evaluate, kill-switch")


if __name__ == "__main__":
    main()
