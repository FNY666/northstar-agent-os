"""Decision table: DMN-shaped rule bookkeeping.

Research motivation: the OMG DMN (Decision Model and Notation) decision
table is the industry-standard way to declare tabular policy --
a list of rules, each with input conditions (field / operator / value)
and an output verdict. A policy engine evaluates an input record against
the table and reports which rule(s) fired. Drools and Camunda execute
the table; this module *books* it deterministically: rule definitions,
evaluation results, and the first-hit verdict, with no actual policy
execution anywhere.

Public API:

- ``DecisionTable()`` -- mutable, RLock-guarded ledger.
  - ``add(rule_id, conditions, output, seq)`` -> frozen ``RuleRecord``:
    books one rule; ``conditions`` is a tuple of ``(field, op, value)``
    triples; ``output`` is the host-declared verdict.
  - ``evaluate(inputs, seq)`` -> frozen ``EvaluationReport``: evaluates
    ``inputs`` against all active rules in rule priority order (add
    order) and books the matched rule ids as data. Pure: books a report,
    never mutates the table.
  - ``hit(inputs)`` -> frozen ``RuleRecord`` or ``None``: the
    first matching rule's record (priority = add order), or ``None`` when
    no rule matches. Pure read view: consumes no seq, writes no audit
    row. Hosts that need the output value call ``hit()`` and read
    ``record.output``.
  - ``rule(rule_id)`` / ``rule_ids()`` / ``stats()`` / ``audit_log()`` --
    pure read views; consume no seq.
- ``decision_table_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records: ``"decision-table.rule-added"``,
  ``"decision-table.evaluated"``, ``"decision-table.rejected"``.

Condition operator vocabulary (pinned, fail-closed on anything else):
``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``, ``in``, ``not-in``.
``in`` / ``not-in`` take a tuple/list of scalar values; numeric
comparisons compare numbers only (bool is not a number here), strings
only with ``==`` / ``!=`` / ``in`` / ``not-in``.

Evaluation semantics: a rule matches when *all* of its conditions match
(conjunctive; an empty condition tuple matches every input -- a catch-all
rule must be added last to be a true fallback). A condition on a field
missing from ``inputs`` does not match (never raised -- DMN reads a
missing entry as "not matching"). Output values are host-declared data;
the module never judges them.

Raw inputs and raw outputs never cross the audit boundary: audit rows
carry rule ids, field names, operators, digest pins, and hit counts --
never ``value`` / ``payload`` / ``inputs`` / ``output``.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* rule tables and *reported* evaluations;
  it executes no policy, enforces nothing, and cannot prove a booked
  evaluation was acted on by the host.
- A ``hit()`` verdict is a ledger answer: "rule R fired for these
  inputs on this host". Whether the host honoured it is the host's
  affair, not this ledger's.
- Conditions on missing fields are no-match as data, never an error.

Version pin: ``decision-table.v1`` / schema pin
``northstar.decision-table.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
DECISION_TABLE_VERSION = "decision-table.v1"

#: Schema pin carried by records and audit events.
DECISION_TABLE_SCHEMA = "northstar.decision-table.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_RULE_ADDED = "decision-table.rule-added"
KIND_EVALUATED = "decision-table.evaluated"
KIND_REJECTED = "decision-table.rejected"

_KINDS = (KIND_RULE_ADDED, KIND_EVALUATED, KIND_REJECTED)

#: Pinned condition operator vocabulary.
OPS = ("==", "!=", "<", "<=", ">", ">=", "in", "not-in")

#: Set membership operators (collection-valued operands).
_SET_OPS = ("in", "not-in")

#: Ordering operators (numbers only; bool is not a number here).
_ORDER_OPS = ("<", "<=", ">", ">=")


class DecisionTableError(Exception):
    """Base class for decision-table errors."""


class BadRuleError(DecisionTableError):
    """Malformed rule id, conditions, or output."""


class DuplicateRuleError(DecisionTableError):
    """Rule id already booked."""


class UnknownRuleError(DecisionTableError):
    """Rule id not found."""


class BadInputError(DecisionTableError):
    """Malformed inputs mapping for evaluation."""


class SeqOrderError(DecisionTableError):
    """Caller seq not a strictly increasing int."""


class AuditKindError(DecisionTableError):
    """Unknown audit kind or banned keys in audit detail."""


def _check_seq(seq: Any) -> None:
    if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
        raise SeqOrderError(f"seq must be a positive int, got {seq!r}")


def _check_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadRuleError(f"{label} must be a non-empty str, got {value!r}")
    return value


def _check_field(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadRuleError(f"condition field must be a non-empty str, got {value!r}")
    return value


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _canonical(obj: Any) -> str:
    if _cj is not None:
        return _cj.jcs_dumps(obj)  # type: ignore[no-any-return]
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _pin(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _check_scalar(value: Any, what: str) -> None:
    """Scalars allowed in condition operands: str/int/float/None (bool is not a number)."""
    if isinstance(value, bool):
        raise BadRuleError(f"{what} must not be a bool, got {value!r}")
    if value is None or isinstance(value, (str, int, float)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise BadRuleError(f"{what} must be a finite number, got {value!r}")
        return
    raise BadRuleError(f"{what} must be a str/int/float/None scalar, got {type(value).__name__}")


def _check_condition(cond: Any, index: int) -> Tuple[str, str, Any]:
    if not (isinstance(cond, (tuple, list)) and len(cond) == 3):
        raise BadRuleError(f"condition {index} must be a (field, op, value) triple")
    field, op, value = cond
    field = _check_field(field)
    if not isinstance(op, str) or op not in OPS:
        raise BadRuleError(f"condition {index} op must be one of {OPS}, got {op!r}")
    if op in _SET_OPS:
        if not isinstance(value, (tuple, list)) or not value:
            raise BadRuleError(f"condition {index} '{op}' needs a non-empty tuple/list")
        for member in value:
            _check_scalar(member, f"condition {index} '{op}' member")
        value = tuple(value)
    else:
        _check_scalar(value, f"condition {index} value")
    return (field, op, value)


def _condition_matches(field: str, op: str, expected: Any, inputs: Mapping[str, Any]) -> bool:
    """Evaluate one condition; missing field is no-match as data."""
    if field not in inputs:
        return False
    actual = inputs[field]
    if op == "==":
        if _is_number(actual) and _is_number(expected):
            return actual == expected
        if isinstance(actual, str) and isinstance(expected, str):
            return actual == expected
        if actual is None and expected is None:
            return True
        return actual is expected or (type(actual) is type(expected) and actual == expected)
    if op == "!=":
        return not _condition_matches(field, "==", expected, inputs)
    if op in _ORDER_OPS:
        if not (_is_number(actual) and _is_number(expected)):
            return False
        if op == "<":
            return actual < expected
        if op == "<=":
            return actual <= expected
        if op == ">":
            return actual > expected
        return actual >= expected
    # "in" / "not-in": members compared with scalar == semantics
    if not _is_number(actual) and not isinstance(actual, str):
        return actual is None and None in expected or False
    matched = False
    for member in expected:
        if _is_number(actual) and _is_number(member):
            if actual == member:
                matched = True
                break
        elif isinstance(actual, str) and isinstance(member, str):
            if actual == member:
                matched = True
                break
        elif actual is None and member is None:
            matched = True
            break
    return matched if op == "in" else not matched


@dataclass(frozen=True)
class RuleRecord:
    """One booked decision-table rule."""

    rule_id: str
    conditions: Tuple[Tuple[str, str, Any], ...]
    output: Any
    output_digest: str
    seq: int
    version: str = DECISION_TABLE_VERSION
    schema: str = DECISION_TABLE_SCHEMA

    def verify(self) -> bool:
        return self.output_digest == _pin(self.output) and self.version == DECISION_TABLE_VERSION


@dataclass(frozen=True)
class EvaluationReport:
    """Outcome of one table evaluation (pure data)."""

    matched_rule_ids: Tuple[str, ...]
    evaluated_rule_ids: Tuple[str, ...]
    seq: int
    version: str = DECISION_TABLE_VERSION
    schema: str = DECISION_TABLE_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "matched_rule_ids": list(self.matched_rule_ids),
            "evaluated_rule_ids": list(self.evaluated_rule_ids),
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RuleView:
    """Read-only digest-only view of one rule."""

    rule_id: str
    condition_count: int
    output_digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "condition_count": self.condition_count,
            "output_digest": self.output_digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class StatsReport:
    """Pure read view of table statistics."""

    rule_count: int
    evaluation_count: int
    total_matches: int
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_count": self.rule_count,
            "evaluation_count": self.evaluation_count,
            "total_matches": self.total_matches,
            "seq": self.seq,
        }


def decision_table_audit_event(kind: str, detail: Mapping[str, Any], seq: int) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the decision table.

    Raw inputs and outputs never cross the audit boundary: ``detail`` may
    carry rule ids, field names, operators, digest pins, counts, and the
    module's own ids -- never ``value``, ``payload``, ``inputs``, or
    ``output``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"value", "payload", "inputs", "output", "condition"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": DECISION_TABLE_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


class DecisionTable:
    """DMN-shaped decision-table ledger.

    Rules are stored in priority order (add order). Evaluation books which
    rules matched in that order; ``hit()`` returns the first matching
    rule's record (or ``None``).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._rules: Dict[str, RuleRecord] = {}
        self._order: List[str] = []
        self._audit: List[Dict[str, Any]] = []
        self._evaluations = 0
        self._total_matches = 0

    # -- internal helpers -------------------------------------------------

    def _claim(self, seq: int) -> None:
        _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not greater than last {self._seq}")

    def _fail(self, seq: int, exc: DecisionTableError, **detail: Any) -> None:
        # Claim-then-burn: the failed mutation consumes its seq.
        self._seq = seq
        detail.setdefault("error", type(exc).__name__)
        self._audit.append(decision_table_audit_event(KIND_REJECTED, detail, seq))
        raise exc

    def _emit(self, kind: str, detail: Dict[str, Any], seq: int) -> None:
        self._seq = seq
        self._audit.append(decision_table_audit_event(kind, detail, seq))

    def _match(self, record: RuleRecord, inputs: Mapping[str, Any]) -> bool:
        return all(
            _condition_matches(field, op, expected, inputs)
            for field, op, expected in record.conditions
        )

    # -- mutations --------------------------------------------------------

    def add(
        self,
        rule_id: str,
        conditions: Tuple[Tuple[str, str, Any], ...],
        output: Any,
        seq: int,
    ) -> RuleRecord:
        """Book one rule with ``(field, op, value)`` conditions."""
        with self._lock:
            try:
                self._claim(seq)
            except SeqOrderError:
                raise
            try:
                rule_id = _check_id(rule_id, "rule_id")
                if rule_id in self._rules:
                    raise DuplicateRuleError(f"rule {rule_id!r} already booked")
                if not isinstance(conditions, (tuple, list)):
                    raise BadRuleError("conditions must be a tuple/list of triples")
                checked = tuple(
                    _check_condition(cond, index)
                    for index, cond in enumerate(conditions)
                )
                if output is None:
                    raise BadRuleError("output must not be None")
                output_digest = _pin(output)
                record = RuleRecord(
                    rule_id=rule_id,
                    conditions=checked,
                    output=output,
                    output_digest=output_digest,
                    seq=seq,
                )
            except DecisionTableError as exc:
                self._fail(seq, exc, rule_id=rule_id if isinstance(rule_id, str) else "")
            self._rules[record.rule_id] = record
            self._order.append(record.rule_id)
            self._emit(
                KIND_RULE_ADDED,
                {
                    "rule_id": record.rule_id,
                    "condition_count": len(record.conditions),
                    "operators": sorted({op for _, op, _ in record.conditions}),
                    "fields": sorted({field for field, _, _ in record.conditions}),
                    "output_digest": record.output_digest,
                },
                seq,
            )
            return record

    def evaluate(self, inputs: Mapping[str, Any], seq: int) -> EvaluationReport:
        """Evaluate ``inputs`` against the table; books matched ids as data."""
        with self._lock:
            try:
                self._claim(seq)
            except SeqOrderError:
                raise
            try:
                if not isinstance(inputs, Mapping):
                    raise BadInputError("inputs must be a mapping")
            except DecisionTableError as exc:
                self._fail(seq, exc)
            matched = tuple(
                rule_id for rule_id in self._order if self._match(self._rules[rule_id], inputs)
            )
            self._evaluations += 1
            self._total_matches += len(matched)
            report = EvaluationReport(
                matched_rule_ids=matched,
                evaluated_rule_ids=tuple(self._order),
                seq=seq,
            )
            self._emit(
                KIND_EVALUATED,
                {
                    "input_fields": sorted(inputs.keys()),
                    "evaluated_rule_count": len(self._order),
                    "matched_rule_ids": list(matched),
                    "match_count": len(matched),
                },
                seq,
            )
            return report

    # -- pure read views --------------------------------------------------

    def hit(self, inputs: Mapping[str, Any]) -> Optional[RuleRecord]:
        """First matching rule's record (priority = add order), or ``None``.

        Pure read: consumes no seq, writes no audit row.
        """
        if not isinstance(inputs, Mapping):
            raise BadInputError("inputs must be a mapping")
        with self._lock:
            for rule_id in self._order:
                record = self._rules[rule_id]
                if self._match(record, inputs):
                    return record
            return None

    def rule(self, rule_id: str) -> RuleRecord:
        with self._lock:
            if rule_id not in self._rules:
                raise UnknownRuleError(f"unknown rule: {rule_id!r}")
            return self._rules[rule_id]

    def rule_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._order)

    def rule_view(self, rule_id: str) -> RuleView:
        with self._lock:
            record = self.rule(rule_id)
            return RuleView(
                rule_id=record.rule_id,
                condition_count=len(record.conditions),
                output_digest=record.output_digest,
                seq=record.seq,
            )

    def stats(self, seq: int) -> StatsReport:
        _check_seq(seq)
        with self._lock:
            return StatsReport(
                rule_count=len(self._rules),
                evaluation_count=self._evaluations,
                total_matches=self._total_matches,
                seq=seq,
            )

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    table = DecisionTable()
    table.add(
        "adult",
        (("age", ">=", 18),),
        "allow",
        seq=1,
    )
    table.add("minor", (("age", "<", 18),), "deny", seq=2)
    record = table.hit({"age": 21})
    assert record is not None and record.rule_id == "adult"
    assert table.hit({"age": 12}).rule_id == "minor"
    assert table.hit({"age": 21, "unknown_field": True}).rule_id == "adult"
    assert table.hit({"name": "no-age"}) is None  # missing field: no-match as data
    report = table.evaluate({"age": 30}, seq=3)
    assert report.matched_rule_ids == ("adult",)
    assert table.stats(seq=4).evaluation_count == 1
    assert len(table.audit_log()) == 3
    print("decision-table OK: add, evaluate, hit, fail-closed, audit")


if __name__ == "__main__":
    main()
