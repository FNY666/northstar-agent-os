"""Rule engine: Drools-shaped condition/action bookkeeping as a deterministic ledger.

House style: frozen dataclasses, caller int seqs strictly increasing, no
wall-clock, RLock-guarded, fail-closed, stdlib-only with the sibling
``canonical_json`` JCS helper behind a try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: this books *declared* rules and *host-declared* evaluations —
it never executes production code paths (actions are opaque host-managed
labels), cannot prove a condition holds on the wire, and condition values are
JCS-canonicalized host-supplied evidence. A booked ``fire`` is a decision the
host claimed, never proof that the host acted.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover
    _cj = None  # type: ignore

#: Module version pin.
RULE_ENGINE_VERSION = "rule-engine.v1"

#: Schema pin carried by records and audit events.
RULE_ENGINE_SCHEMA = "northstar.rule-engine.v1"

#: Audit event envelope format.
_AUDIT_FORMAT = "audit.ndjson/1"

#: Operator vocabulary for fact matching.
OPERATORS = frozenset(
    {"==", "!=", ">", "<", ">=", "<=", "in", "not-in", "contains"}
)

#: Field-name shape: non-empty, <= 256 chars, no whitespace.
_MAX_FIELD_LEN = 256

#: Max conditions per rule.
_MAX_CONDITIONS = 64

#: Max rules per engine instance.
_MAX_RULES = 4096


def _canonical(value: Any) -> str:
    """Deterministic string form of a JSON-safe value (digest inputs)."""
    if _cj is not None:
        try:
            raw = _cj.encode(value)  # type: ignore[attr-defined]
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        except Exception:
            pass
    import json as _json

    return _json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(*parts: str) -> str:
    """Domain-separated ``sha256:`` digest pin over digest inputs."""
    h = hashlib.sha256()
    h.update("northstar.rule-engine.v1".encode("utf-8"))
    for part in parts:
        h.update(b"\x00")
        h.update(part.encode("utf-8"))
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Fail-closed taxonomy
# ---------------------------------------------------------------------------


class RuleEngineError(Exception):
    """Base error for the rule engine ledger."""


class BadRuleError(RuleEngineError):
    """Rule id is malformed."""


class DuplicateRuleError(RuleEngineError):
    """Rule id already booked (ids never recycled)."""


class UnknownRuleError(RuleEngineError):
    """Rule id not on the books."""


class BadConditionError(RuleEngineError):
    """A condition is malformed or uses an unknown operator."""


class BadFactError(RuleEngineError):
    """Evaluation facts are malformed."""


class BadActionError(RuleEngineError):
    """Action label is malformed."""


class RuleMismatchError(RuleEngineError):
    """Conditions do not hold for the supplied facts (fire refused)."""


class SeqOrderError(RuleEngineError):
    """Seq is not a strictly increasing caller int."""


class AuditKindError(RuleEngineError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


def _check_id(value: Any, error: type) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise error("id must be a non-empty str")
    if not value or len(value) > _MAX_FIELD_LEN or any(c.isspace() for c in value):
        raise error("id must be non-empty, <= 256 chars, no whitespace")
    return value


def _check_seq(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise SeqOrderError("seq must be a strict int")
    if value < 0:
        raise SeqOrderError("seq must be non-negative")
    return value


def _check_value(value: Any) -> None:
    """Facts/condition values: JSON-safe scalars only (bool != int)."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        if isinstance(value, bool):
            raise BadConditionError("bool values are not supported; use 0/1")
        if isinstance(value, int) and abs(value) >= 2**53:
            raise BadConditionError("unsafe integer outside |n| < 2^53")
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise BadConditionError("non-finite floats refused")
        return
    if isinstance(value, str):
        if len(value) > 65536:
            raise BadConditionError("string value too long")
        return
    raise BadConditionError("values must be None/bool/int/float/str")


@dataclass(frozen=True)
class Condition:
    """One fact-matching predicate of a rule (AND across conditions)."""

    field: str
    operator: str
    value: Any

    def __post_init__(self) -> None:
        _check_id(self.field, BadConditionError)
        if self.operator not in OPERATORS:
            raise BadConditionError("unknown operator: %r" % (self.operator,))
        if self.operator in ("in", "not-in"):
            if not isinstance(self.value, (list, tuple)):
                raise BadConditionError("'in'/'not-in' require a list value")
            for item in self.value:
                _check_value(item)
        else:
            _check_value(self.value)

    def matches(self, facts: Mapping[str, Any]) -> bool:
        """Pure predicate: True when this condition holds on ``facts``."""
        actual = facts.get(self.field)
        if self.operator == "==":
            return actual == self.value
        if self.operator == "!=":
            return actual != self.value
        if self.operator in (">", "<", ">=", "<="):
            if not isinstance(actual, (int, float)) or isinstance(actual, bool):
                return False
            if not isinstance(self.value, (int, float)) or isinstance(self.value, bool):
                return False
            if self.operator == ">":
                return actual > self.value
            if self.operator == "<":
                return actual < self.value
            if self.operator == ">=":
                return actual >= self.value
            return actual <= self.value
        if self.operator == "in":
            return actual in self.value
        if self.operator == "not-in":
            return actual not in self.value
        if self.operator == "contains":
            if isinstance(actual, str) and isinstance(self.value, str):
                return self.value in actual
            if isinstance(actual, (list, tuple)):
                return self.value in actual
            return False
        return False  # unreachable: operator vocabulary pinned

    def digest(self) -> str:
        return _digest(self.field, self.operator, _canonical(self.value))


@dataclass(frozen=True)
class RuleRecord:
    """One registered rule: ordered conditions + opaque action label."""

    rule_id: str
    conditions: Tuple[Condition, ...]
    action: str
    priority: int
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            self.rule_id,
            _canonical([c.digest() for c in self.conditions]),
            self.action,
            str(self.priority),
            str(self.seq),
        )

    def holds(self, facts: Mapping[str, Any]) -> bool:
        """True when every condition matches (AND semantics)."""
        return all(c.matches(facts) for c in self.conditions)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "conditions": [
                {"field": c.field, "operator": c.operator, "value": c.value}
                for c in self.conditions
            ],
            "action": self.action,
            "priority": self.priority,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class EvaluationReport:
    """Pure view of which rules hold on a fact set (seq validated, not consumed)."""

    fact_digest: str
    matched_rule_ids: Tuple[str, ...]
    matched_count: int
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "fact_digest": self.fact_digest,
            "matched_rule_ids": list(self.matched_rule_ids),
            "matched_count": self.matched_count,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class FireRecord:
    """A booked rule execution decision: conditions held, action declared."""

    rule_id: str
    fact_digest: str
    action: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            self.rule_id, self.fact_digest, self.action, str(self.seq)
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "fact_digest": self.fact_digest,
            "action": self.action,
            "seq": self.seq,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = frozenset({"rule-added", "rule-fired", "rejected"})


def rule_engine_audit_event(
    rule_engine: "RuleEngine", kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for the rule engine.

    Raw fact values and condition values never cross the audit boundary —
    only digests, ids, field names, operators, and counts.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError("unknown audit kind: %r" % (kind,))
    banned = ("facts", "value", "payload", "raw", "body", "data")
    for key in detail:
        for word in banned:
            if word in key:
                raise AuditKindError("banned key in audit detail: %r" % (key,))
    _check_seq(seq)
    return {
        "format": _AUDIT_FORMAT,
        "module": RULE_ENGINE_VERSION,
        "schema": RULE_ENGINE_SCHEMA,
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------


class RuleEngine:
    """Deterministic single-host Drools-shaped rule ledger.

    ``add`` pins rules, ``evaluate`` is a pure read view of which rules hold
    on a host-supplied fact set, and ``fire`` books one execution decision.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._rules: Dict[str, RuleRecord] = {}
        self._fires: List[FireRecord] = []
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline -----------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq
        return seq

    def _fail(self, seq: int, exc: RuleEngineError, **detail: Any) -> RuleEngineError:
        self._claim(seq)
        self._audit.append(
            rule_engine_audit_event(self, "rejected", seq, error=type(exc).__name__, **detail)
        )
        return exc

    # -- mutations ----------------------------------------------------------

    def add(
        self,
        rule_id: str,
        conditions: Sequence[Mapping[str, Any] | Condition],
        action: str,
        seq: int,
        priority: int = 0,
    ) -> RuleRecord:
        """Register a rule (conditions ANDed); duplicate ids refused."""
        with self._lock:
            try:
                rule_id = _check_id(rule_id, BadRuleError)
                if rule_id in self._rules:
                    raise DuplicateRuleError("duplicate rule id: %r" % (rule_id,))
                if len(self._rules) >= _MAX_RULES:
                    raise BadRuleError("engine full")
                if not conditions or len(conditions) > _MAX_CONDITIONS:
                    raise BadConditionError("1..%d conditions required" % _MAX_CONDITIONS)
                conds: List[Condition] = []
                for raw in conditions:
                    if isinstance(raw, Condition):
                        conds.append(raw)
                    elif isinstance(raw, Mapping):
                        conds.append(
                            Condition(
                                field=raw.get("field"),
                                operator=raw.get("operator"),
                                value=raw.get("value"),
                            )
                        )
                    else:
                        raise BadConditionError("condition must be a mapping or Condition")
                if not isinstance(action, str) or not action or len(action) > _MAX_FIELD_LEN:
                    raise BadActionError("action must be a non-empty short label")
                if not isinstance(priority, int) or isinstance(priority, bool):
                    raise BadRuleError("priority must be a strict int")
            except RuleEngineError as exc:
                raise self._fail(seq, exc, rule_id=str(rule_id))
            seq = self._claim(seq)
            digest = _digest(
                rule_id,
                _canonical([c.digest() for c in conds]),
                action,
                str(priority),
                str(seq),
            )
            record = RuleRecord(
                rule_id=rule_id,
                conditions=tuple(conds),
                action=action,
                priority=priority,
                seq=seq,
                digest=digest,
            )
            self._rules[rule_id] = record
            self._audit.append(
                rule_engine_audit_event(
                    self,
                    "rule-added",
                    seq,
                    rule_id=rule_id,
                    condition_count=len(conds),
                    priority=priority,
                    digest=digest,
                )
            )
            return record

    def fire(self, rule_id: str, facts: Mapping[str, Any], seq: int) -> FireRecord:
        """Book one execution decision: rule must exist and conditions must hold."""
        with self._lock:
            try:
                _check_id(rule_id, UnknownRuleError)
                record = self._rules.get(rule_id)
                if record is None:
                    raise UnknownRuleError("unknown rule: %r" % (rule_id,))
                facts = _facts_map(facts)
                if not record.holds(facts):
                    raise RuleMismatchError("conditions do not hold for %r" % (rule_id,))
            except RuleEngineError as exc:
                raise self._fail(seq, exc, rule_id=str(rule_id))
            seq = self._claim(seq)
            fact_digest = _digest("facts", _canonical(sorted(facts.items())))
            digest = _digest(rule_id, fact_digest, record.action, str(seq))
            row = FireRecord(
                rule_id=rule_id,
                fact_digest=fact_digest,
                action=record.action,
                seq=seq,
                digest=digest,
            )
            self._fires.append(row)
            self._audit.append(
                rule_engine_audit_event(
                    self,
                    "rule-fired",
                    seq,
                    rule_id=rule_id,
                    action=record.action,
                    fact_digest=fact_digest,
                    digest=digest,
                )
            )
            return row

    # -- pure read views -----------------------------------------------------

    def evaluate(self, facts: Mapping[str, Any], seq: int) -> EvaluationReport:
        """Pure view: which rules hold on ``facts`` (seq validated, not consumed).

        Matches sort by priority (desc), then rule_id (asc) — the agenda order.
        """
        with self._lock:
            facts = _facts_map(facts)
            _check_seq(seq)  # validated, not consumed
            fact_digest = _digest("facts", _canonical(sorted(facts.items())))
            matched = [r for r in self._rules.values() if r.holds(facts)]
            matched.sort(key=lambda r: (-r.priority, r.rule_id))
            return EvaluationReport(
                fact_digest=fact_digest,
                matched_rule_ids=tuple(r.rule_id for r in matched),
                matched_count=len(matched),
                seq=seq,
            )

    def rule(self, rule_id: str) -> Optional[RuleRecord]:
        with self._lock:
            return self._rules.get(rule_id)

    def rule_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._rules))

    def fires_for(self, rule_id: str) -> Tuple[FireRecord, ...]:
        with self._lock:
            return tuple(f for f in self._fires if f.rule_id == rule_id)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "rules": len(self._rules),
                "fires": len(self._fires),
                "seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def _facts_map(facts: Any) -> Dict[str, Any]:
    if not isinstance(facts, Mapping):
        raise BadFactError("facts must be a mapping")
    result: Dict[str, Any] = {}
    for key, value in facts.items():
        if not isinstance(key, str) or not key or len(key) > _MAX_FIELD_LEN:
            raise BadFactError("fact keys must be short non-empty strings")
        _check_value(value)
        result[key] = value
    return result


def main() -> None:
    engine = RuleEngine()
    engine.add(
        "adult-discount",
        [{"field": "age", "operator": ">=", "value": 18}, {"field": "vip", "operator": "==", "value": True}],
        action="apply-discount",
        seq=1,
        priority=5,
    )
    engine.add(
        "senior-free",
        [{"field": "age", "operator": ">=", "value": 65}],
        action="free-shipping",
        seq=2,
        priority=10,
    )
    report = engine.evaluate({"age": 70, "vip": True}, seq=2)
    assert report.matched_rule_ids == ("senior-free", "adult-discount")
    fire = engine.fire("senior-free", {"age": 70, "vip": True}, seq=3)
    assert fire.verify()
    assert engine.rule("adult-discount").verify()
    print("rule-engine OK: add, evaluate, fire, agenda, pins, audit")


if __name__ == "__main__":
    main()
