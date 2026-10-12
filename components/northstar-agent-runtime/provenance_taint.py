"""Provenance-tracked taint + fail-closed security automata + per-tool budgets
(eighty-eighth batch).

Absorbed from ``ovidiu-eremia/llm-agent-guardians`` (MIT) — Erik Meijer's
*"Guardians of the Agents"* (CACM, Jan 2026). Thesis: prompt injection is
SQL injection — code and data are not separated; the fix is to separate
them. Guardians splits the agent loop into **generate → verify → execute**:
the LLM plans a workflow AST with ``SymRef`` placeholders, a static
verifier checks it against a declarative policy, and the executor runs the
verified plan with runtime monitoring as defense in depth.

Mechanics ported here (adapted to Northstar's per-call dispatch model —
there is no workflow AST here, so the automaton engine is the runtime
analogue of the verifier's abstract execution):

* **Provenance-tracked taint** (``verify.py``: ``AbstractValue``,
  ``_is_tainted_for_rule``). A value carries taint *labels* **and** a
  transitive *provenance* set (every tool whose output contributed to it).
  A taint rule fires only on the **conjunction** of label overlap with the
  source's declared labels **and** the source tool appearing in the value's
  provenance. Label-only taint raises false positives when unrelated tools
  share label names; the provenance check is Guardians' own extension
  beyond the paper, and it is ported exactly.
* **Fail-closed security automata** (``verify.py::_check_automata``).
  Automata track a *set* of possible states (nondeterministic); each tool
  call fires the first transition matching ``(from_state, tool_name)``
  whose optional condition holds over the call's arguments. Reaching an
  ``is_error`` state is a violation. Two fail-closed rules are ported
  verbatim: an **unparseable condition is assumed to fire**, and a
  condition referencing **symbolic/unknown values is assumed to fire** —
  uncertainty can only deny, never allow.
* **``safe_eval``** (AST-allowlisted expression evaluator, stdlib ``ast``).
  Replaces ``eval()`` for automaton/condition expressions. Permits only:
  literals, names (env lookup), lists/tuples, comparisons, boolean ops,
  ``not``, ``in``/``not in``, and ``len()`` calls. Anything else raises —
  and the caller treats the raise as "condition fires" (fail-closed).
* **Per-tool budgets** (``execute.py::WorkflowExecutor(budgets=...)``).
  Guardians enforces call-count caps at execution and raises
  ``SecurityViolation`` when exceeded. Here the cap is per tool name
  (``{"send_email": 3}``); exceeding it denies the call. Malformed limits
  fail closed.

Honest scope (deliberately not ported):

* No Z3 — ``z3-solver`` is a non-stdlib dependency and this repo is
  stdlib-only; the automaton + taint conjunction covers the
  sequence/dataflow invariants this batch targets.
* No static AST verification pass — Northstar dispatches one tool call at
  a time through its approval gate, so the check happens per call at
  runtime (the same defense-in-depth role the executor plays in
  Guardians).
* No loop unrolling — long-horizon repetition is bounded by the budget
  enforcer instead.
"""

from __future__ import annotations

import ast
import hashlib
import math
import operator
import threading
import uuid
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

try:
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - standalone use
    import json as _json

    def jcs_canonical_json(value: Any) -> bytes:
        return _json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


_MAX_SANITIZER_DIGEST_NODES = 32_768
_MAX_SANITIZER_DIGEST_DEPTH = 64
_MAX_SANITIZER_DIGEST_BYTES = 2 * 1024 * 1024
_MAX_SANITIZER_DIGEST_STRING_CHARS = 1024 * 1024


def _content_digest(value: Any) -> str | None:
    """Fingerprint bounded JSON-shaped data; unsupported data fails closed."""
    remaining_nodes = [_MAX_SANITIZER_DIGEST_NODES]
    remaining_bytes = [_MAX_SANITIZER_DIGEST_BYTES]
    active: set[int] = set()

    def validate(item: Any, depth: int) -> bool:
        remaining_nodes[0] -= 1
        if remaining_nodes[0] < 0 or depth > _MAX_SANITIZER_DIGEST_DEPTH:
            return False
        item_type = type(item)
        if item is None or item_type is bool:
            return True
        if item_type is int:
            return item.bit_length() <= 4096
        if item_type is float:
            return math.isfinite(item)
        if item_type is str:
            if len(item) > _MAX_SANITIZER_DIGEST_STRING_CHARS:
                return False
            try:
                size = len(item.encode("utf-8"))
            except UnicodeEncodeError:
                return False
            remaining_bytes[0] -= size
            return remaining_bytes[0] >= 0
        if item_type not in (list, tuple, dict) or len(item) > _MAX_SANITIZER_DIGEST_NODES:
            return False
        identity = id(item)
        if identity in active:
            return False
        active.add(identity)
        try:
            if item_type is dict:
                for key, child in item.items():
                    if type(key) is not str or not validate(key, depth + 1):
                        return False
                    if not validate(child, depth + 1):
                        return False
            else:
                for child in item:
                    if not validate(child, depth + 1):
                        return False
            return True
        finally:
            active.remove(identity)

    if not validate(value, 0):
        return None
    try:
        return hashlib.sha256(jcs_canonical_json(value)).hexdigest()
    except (TypeError, ValueError, RecursionError):
        return None


# ---------------------------------------------------------------------------
# safe_eval: AST-allowlisted expression evaluator (port of safe_eval.py)
# ---------------------------------------------------------------------------

_CMP_OPS = {
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}

_MAX_CONDITION_VALUE_DEPTH = 32
_MAX_CONDITION_VALUE_NODES = 4096
_MAX_CONDITION_TEXT_CHARS = 65_536
_MAX_CONDITION_INT_BITS = 256
_MAPPING_PROXY_TYPE = type(MappingProxyType({}))


def _validate_condition_value(value: Any) -> Any:
    """Accept only bounded, exact JSON-like types before operators touch values."""
    remaining = [_MAX_CONDITION_VALUE_NODES]
    active: set[int] = set()

    def visit(item: Any, depth: int) -> Any:
        remaining[0] -= 1
        if remaining[0] < 0 or depth > _MAX_CONDITION_VALUE_DEPTH:
            raise ValueError("condition value exceeds structural limits")
        item_type = type(item)
        if item is None or item_type is bool:
            return item
        if item_type is int:
            if item.bit_length() > _MAX_CONDITION_INT_BITS:
                raise ValueError("condition integer exceeds bit limit")
            return item
        if item_type is float:
            if not math.isfinite(item):
                raise ValueError("condition float must be finite")
            return item
        if item_type is str:
            if len(item) > _MAX_CONDITION_TEXT_CHARS:
                raise ValueError("condition string exceeds size limit")
            return item
        if item_type not in (list, tuple, dict, _MAPPING_PROXY_TYPE):
            raise ValueError(f"unsupported condition value type: {item_type.__name__}")
        if len(item) > _MAX_CONDITION_VALUE_NODES:
            raise ValueError("condition container exceeds item limit")
        identity = id(item)
        if identity in active:
            raise ValueError("cyclic condition value")
        active.add(identity)
        try:
            if item_type in (dict, _MAPPING_PROXY_TYPE):
                out = {}
                for key, child in item.items():
                    if type(key) is not str or len(key) > _MAX_CONDITION_TEXT_CHARS:
                        raise ValueError("condition object keys must be bounded strings")
                    out[key] = visit(child, depth + 1)
                return out
            values = [visit(child, depth + 1) for child in item]
            return values if item_type is list else tuple(values)
        finally:
            active.remove(identity)

    return visit(value, 0)


def _freeze_condition_value(value: Any) -> Any:
    """Recursively detach policy constants and make every container immutable."""
    item_type = type(value)
    if item_type is dict:
        return MappingProxyType({key: _freeze_condition_value(child) for key, child in value.items()})
    if item_type in (list, tuple):
        return tuple(_freeze_condition_value(child) for child in value)
    return value


def _condition_equal(left: Any, right: Any) -> bool:
    """JSON-style equality that never conflates booleans with numbers."""
    left_type, right_type = type(left), type(right)
    if left_type is bool and right_type in (int, float) or right_type is bool and left_type in (int, float):
        raise ValueError("condition comparison mixes boolean and numeric types")
    if left_type is dict and right_type is dict:
        return left.keys() == right.keys() and all(
            _condition_equal(left[key], right[key]) for key in left
        )
    if left_type in (list, tuple) and right_type is left_type:
        return len(left) == len(right) and all(
            _condition_equal(a, b) for a, b in zip(left, right)
        )
    if left_type is not right_type and not (
        left_type in (int, float) and right_type in (int, float)
    ):
        return False
    return operator.eq(left, right)


def _condition_contains(container: Any, value: Any) -> bool:
    if type(container) is str:
        if type(value) is not str:
            raise ValueError("string membership requires a string value")
        return value in container
    if type(container) is dict:
        if type(value) is not str:
            raise ValueError("object membership requires a string key")
        return value in container
    if type(container) in (list, tuple):
        return any(_condition_equal(item, value) for item in container)
    raise ValueError("membership requires a string, list, tuple, or object")


def safe_eval(expr: str, env: dict[str, Any]) -> Any:
    """Evaluate a simple expression safely against *env*.

    Raises :class:`ValueError` on anything outside the allowlist. Callers
    treat the raise as "condition fires" — fail-closed, exactly as in
    Guardians' ``_check_automata``.
    """
    if not isinstance(expr, str) or len(expr) > 4096:
        raise ValueError("condition expression is missing or too long")
    if type(env) is not dict:
        raise ValueError("condition environment must be a plain dict")
    try:
        tree = ast.parse(expr, mode="eval")
    except (SyntaxError, RecursionError, MemoryError) as error:
        raise ValueError("condition expression cannot be parsed") from error
    if sum(1 for _ in ast.walk(tree)) > 1024:
        raise ValueError("condition expression has too many nodes")
    return _eval_node(tree.body, env)


def _eval_condition(expr: str, env: dict[str, Any]) -> bool:
    """Require a boolean policy result; truthiness is not policy semantics."""
    result = safe_eval(expr, env)
    if type(result) is not bool:
        raise ValueError("condition expression must evaluate to bool")
    return result


def _eval_node(node: ast.expr, env: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return _validate_condition_value(node.value)
    if isinstance(node, ast.Name):
        try:
            return _validate_condition_value(env[node.id])
        except KeyError:
            raise ValueError(f"undefined variable: {node.id!r}")
    if isinstance(node, ast.List):
        return [_eval_node(e, env) for e in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_eval_node(e, env) for e in node.elts)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_node(node.operand, env)
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            result: Any = True
            for v in node.values:
                result = _eval_node(v, env)
                if not result:
                    return result
            return result
        if isinstance(node.op, ast.Or):
            result = False
            for v in node.values:
                result = _eval_node(v, env)
                if result:
                    return result
            return result
        raise ValueError(f"disallowed boolean op: {type(node.op).__name__}")
    if isinstance(node, ast.Compare):
        current = _eval_node(node.left, env)
        for op, comp_node in zip(node.ops, node.comparators):
            comp_val = _eval_node(comp_node, env)
            if isinstance(op, ast.In):
                if not _condition_contains(comp_val, current):
                    return False
            elif isinstance(op, ast.NotIn):
                if _condition_contains(comp_val, current):
                    return False
            elif isinstance(op, (ast.Eq, ast.NotEq)):
                equal = _condition_equal(current, comp_val)
                if equal != isinstance(op, ast.Eq):
                    return False
            else:
                fn = _CMP_OPS.get(type(op))
                if fn is None:
                    raise ValueError(
                        f"disallowed comparison: {type(op).__name__}"
                    )
                if type(current) is bool or type(comp_val) is bool:
                    raise ValueError("ordering comparisons do not accept booleans")
                if type(current) not in (str, int, float) or type(comp_val) not in (str, int, float):
                    raise ValueError("ordering comparisons require scalar values")
                if type(current) is not type(comp_val) and not (
                    type(current) in (int, float) and type(comp_val) in (int, float)
                ):
                    raise ValueError("ordering comparison types do not match")
                if not fn(current, comp_val):
                    return False
            current = comp_val
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "len"
        and len(node.args) == 1
        and not node.keywords
    ):
        return len(_eval_node(node.args[0], env))
    raise ValueError(f"disallowed expression: {type(node).__name__}")


def expr_names(expr: str) -> set[str]:
    """Names referenced by an expression (for symbolic detection).

    Excludes the allowlisted builtin ``len`` (it is not a variable).
    """
    if not isinstance(expr, str) or len(expr) > 4096:
        return set()
    try:
        tree = ast.parse(expr, mode="eval")
    except (SyntaxError, RecursionError, MemoryError):
        return set()
    return {
        n.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Name) and n.id != "len"
    }


# ---------------------------------------------------------------------------
# Taint values: labels + transitive provenance
# ---------------------------------------------------------------------------


@dataclass
class TaintedValue:
    """A runtime value with taint metadata.

    Tools receive the unwrapped ``raw``; the gate tracks ``labels``.
    ``provenance`` is the transitive set of tool names whose outputs
    contributed to this value (Guardians' ``AbstractValue.provenance``).
    """

    raw: Any
    labels: set[str] = field(default_factory=set)
    provenance: set[str] = field(default_factory=set)
    source_tool: str = "unknown"
    sanitized_for: set[str] = field(default_factory=set)
    sanitized_digests: dict[str, str] = field(default_factory=dict)

    def copy(self) -> "TaintedValue":
        return TaintedValue(
            raw=self.raw,
            labels=set(self.labels),
            provenance=set(self.provenance),
            source_tool=self.source_tool,
            sanitized_for=set(self.sanitized_for),
            sanitized_digests=dict(self.sanitized_digests),
        )


def _unwrap(val: Any) -> Any:
    if isinstance(val, TaintedValue):
        return val.raw
    if isinstance(val, dict):
        return {k: _unwrap(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_unwrap(v) for v in val]
    return val


def _walk_tainted(val: Any, out: list[TaintedValue]) -> None:
    if isinstance(val, TaintedValue):
        out.append(val)
    elif isinstance(val, dict):
        for v in val.values():
            _walk_tainted(v, out)
    elif isinstance(val, list):
        for v in val:
            _walk_tainted(v, out)


def find_tainted(val: Any) -> list[TaintedValue]:
    """All tainted values nested anywhere inside *val*."""
    out: list[TaintedValue] = []
    _walk_tainted(val, out)
    return out


# ---------------------------------------------------------------------------
# Policy declarations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolTaintSpec:
    """Declared taint behavior of one tool (Guardians' ``ToolSpec`` core).

    ``source_labels``: labels this tool's output carries (e.g. a mail
    fetcher emits ``{"secret"}``).
    ``sink_params``: argument names treated as sinks for taint rules.
    ``sanitizes``: taint-rule names this tool sanitizes for — values it
    produces are marked ``sanitized_for`` those rules.
    """

    name: str
    source_labels: tuple[str, ...] = ()
    sink_params: tuple[str, ...] = ()
    sanitizes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name or len(self.name) > 256:
            raise ValueError("tool taint spec name must be a non-empty string <= 256 characters")
        for field_name in ("source_labels", "sink_params", "sanitizes"):
            values = getattr(self, field_name)
            if type(values) not in (tuple, list) or len(values) > 256:
                raise ValueError(f"{field_name} must be a bounded list/tuple of names")
            if any(type(value) is not str or not value or len(value) > 256 for value in values):
                raise ValueError(f"{field_name} entries must be non-empty strings <= 256 characters")
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} entries must be unique")
            object.__setattr__(self, field_name, tuple(values))


@dataclass(frozen=True)
class TaintRule:
    """Data-flow rule: tainted data must not reach a sink.

    Port of Guardians' ``TaintRule``. Fires when a value passed to
    ``sink_tool.sink_param`` carries overlapping ``source_labels`` **and**
    ``source_tool`` in its transitive provenance. A tool with no
    registered spec cannot be reasoned about — the gate denies (the
    "missing spec" violation).
    """

    name: str
    source_tool: str
    source_labels: tuple[str, ...]
    sink_tool: str
    sink_param: str
    condition: str | None = None
    sanitizers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in ("name", "source_tool", "sink_tool", "sink_param"):
            value = getattr(self, field_name)
            if type(value) is not str or not value or len(value) > 256:
                raise ValueError(f"taint rule {field_name} must be a non-empty string <= 256 characters")
        for field_name in ("source_labels", "sanitizers"):
            values = getattr(self, field_name)
            if type(values) not in (tuple, list) or len(values) > 256:
                raise ValueError(f"taint rule {field_name} must be a bounded list/tuple of names")
            if any(type(value) is not str or not value or len(value) > 256 for value in values):
                raise ValueError(f"taint rule {field_name} entries must be non-empty strings <= 256 characters")
            if len(values) != len(set(values)):
                raise ValueError(f"taint rule {field_name} entries must be unique")
            object.__setattr__(self, field_name, tuple(values))
        if self.condition is not None and (type(self.condition) is not str or len(self.condition) > 4096):
            raise ValueError("taint rule condition must be text <= 4096 characters")


@dataclass(frozen=True)
class AutomatonState:
    name: str
    is_error: bool = False


@dataclass(frozen=True)
class AutomatonTransition:
    """Transition fired by a tool call.

    Matches ``(from_state, tool_name)``; the optional ``condition`` is a
    ``safe_eval`` expression over ``{**call_args, **automaton.constants}``.
    """

    from_state: str
    tool_name: str
    to_state: str
    condition: str | None = None


@dataclass(frozen=True)
class SecurityAutomaton:
    """Sequence invariant as a finite automaton (Guardians' ``Policy.automata``)."""

    name: str
    states: tuple[AutomatonState, ...]
    initial_state: str
    transitions: tuple[AutomatonTransition, ...] = ()
    constants: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name or len(self.name) > 128:
            raise ValueError("automaton name must be a non-empty string <= 128 characters")
        if type(self.states) is not tuple or not self.states:
            raise ValueError("automaton states must be a non-empty tuple")
        names: set[str] = set()
        for state in self.states:
            if type(state) is not AutomatonState or type(state.name) is not str or not state.name:
                raise ValueError("automaton states must have non-empty names")
            if state.name in names:
                raise ValueError(f"duplicate automaton state: {state.name!r}")
            names.add(state.name)
            if type(state.is_error) is not bool:
                raise ValueError("automaton state is_error must be bool")
        if type(self.initial_state) is not str or self.initial_state not in names:
            raise ValueError("automaton initial_state must name a declared state")
        if next(state for state in self.states if state.name == self.initial_state).is_error:
            raise ValueError("automaton initial_state cannot be an error state")
        if type(self.transitions) is not tuple:
            raise ValueError("automaton transitions must be a tuple")
        for transition in self.transitions:
            if type(transition) is not AutomatonTransition:
                raise ValueError("automaton transitions must be AutomatonTransition values")
            if transition.from_state not in names or transition.to_state not in names:
                raise ValueError("automaton transition references an undeclared state")
            if type(transition.tool_name) is not str or not transition.tool_name:
                raise ValueError("automaton transition tool_name must be non-empty")
            if transition.condition is not None and (
                type(transition.condition) is not str or len(transition.condition) > 4096
            ):
                raise ValueError("automaton condition must be text <= 4096 characters")
        if type(self.constants) is not dict or any(type(key) is not str for key in self.constants):
            raise ValueError("automaton constants must be a plain dict with string keys")
        try:
            validated_constants = _validate_condition_value(self.constants)
        except ValueError as error:
            raise ValueError(f"invalid automaton constants: {error}") from error
        object.__setattr__(self, "constants", _freeze_condition_value(validated_constants))


@dataclass(frozen=True)
class BudgetLimit:
    """Per-tool call-count cap. Non-positive / non-int limits are malformed."""

    tool_name: str
    max_calls: int


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    check: str  # "budget" | "automaton" | "taint" | "ok"
    detail: dict[str, Any] = field(default_factory=dict)
    budget_reservation: str = field(default="", repr=False, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "check": self.check,
            "detail": dict(self.detail),
        }


# ---------------------------------------------------------------------------
# Taint rule evaluation (port of _is_tainted_for_rule)
# ---------------------------------------------------------------------------


def _taint_rule_fires(
    value: TaintedValue,
    rule: TaintRule,
    arg_env: dict[str, Any],
    constants: dict[str, Any],
) -> bool:
    """Whether *value* violates *rule*.

    Conjunction, exactly as in Guardians: label overlap with the source's
    declared labels **and** the source tool in the value's provenance.
    Already-sanitized values never fire. A conditional rule only *excuses*
    the flow when it concretely evaluates to false; anything else
    (unparseable, symbolic, exception) applies the rule — fail-closed.
    """
    if rule.source_labels:
        if not (value.labels & set(rule.source_labels)):
            return False
        # The provenance check: the declared source must actually be in
        # this value's data lineage. Prevents false positives when
        # unrelated tools share label names.
        if rule.source_tool not in value.provenance:
            return False
    elif not value.labels:
        return False

    if rule.name in value.sanitized_for:
        pinned = value.sanitized_digests.get(rule.name)
        current = _content_digest(value.raw)
        if pinned is not None and current == pinned:
            return False

    if rule.condition:
        eval_env: dict[str, Any] = {}
        eval_env.update(arg_env)
        eval_env.update(constants)
        refs = expr_names(rule.condition)
        # Symbolic / unknown names: apply the rule conservatively.
        if any(n not in eval_env for n in refs):
            return True
        try:
            if not _eval_condition(rule.condition, eval_env):
                return False
        except Exception:
            return True  # can't evaluate — apply conservatively

    return True


class TaintTracker:
    """Tracks tainted values across tool calls and checks sink rules."""

    def __init__(
        self,
        specs: dict[str, ToolTaintSpec] | None = None,
        rules: list[TaintRule] | None = None,
        constants: dict[str, Any] | None = None,
    ) -> None:
        if specs is not None and type(specs) is not dict:
            raise ValueError("taint specs must be a plain dict")
        raw_specs = dict(specs or {})
        if len(raw_specs) > 4096 or any(
            type(name) is not str or type(spec) is not ToolTaintSpec or spec.name != name
            for name, spec in raw_specs.items()
        ):
            raise ValueError("taint specs must map each tool name to its matching validated spec")
        if rules is not None and type(rules) not in (list, tuple):
            raise ValueError("taint rules must be a list or tuple")
        raw_rules = list(rules or [])
        if len(raw_rules) > 4096 or any(type(rule) is not TaintRule for rule in raw_rules):
            raise ValueError("taint rules must contain only validated TaintRule values")
        rule_names = [rule.name for rule in raw_rules]
        if len(rule_names) != len(set(rule_names)):
            raise ValueError("taint rule names must be unique")
        if constants is not None and type(constants) is not dict:
            raise ValueError("taint constants must be a plain dict")
        raw_constants = dict(constants or {})
        if any(type(key) is not str for key in raw_constants):
            raise ValueError("taint constant names must be strings")
        try:
            frozen_constants = _freeze_condition_value(_validate_condition_value(raw_constants))
        except ValueError as error:
            raise ValueError(f"invalid taint constants: {error}") from error
        self._specs = raw_specs
        self._rules = raw_rules
        self._constants = frozen_constants
        self._env: dict[str, TaintedValue] = {}

    # -- value lifecycle -------------------------------------------------

    def produce(self, tool_name: str, raw: Any) -> TaintedValue:
        """Wrap a tool's output: labels = spec labels, provenance = {tool}."""
        spec = self._specs.get(tool_name)
        labels = set(spec.source_labels) if spec else set()
        return TaintedValue(
            raw=raw,
            labels=labels,
            provenance={tool_name},
            source_tool=tool_name,
        )

    def derive(
        self, tool_name: str, raw: Any, inputs: dict[str, Any]
    ) -> TaintedValue:
        """Wrap a computed value: union of input labels + provenance.

        Mirrors Guardians' abstract-result construction: ``labels =
        spec_labels | input_labels``, ``provenance = {tool} |
        input_provenance``.
        """
        tainted = find_tainted(inputs)
        labels: set[str] = set()
        provenance: set[str] = {tool_name}
        for t in tainted:
            labels |= t.labels
            provenance |= t.provenance
        spec = self._specs.get(tool_name)
        if spec:
            labels |= set(spec.source_labels)
        return TaintedValue(
            raw=raw, labels=labels, provenance=provenance, source_tool=tool_name
        )

    def bind(self, name: str, value: TaintedValue) -> None:
        self._env[name] = value

    def lookup(self, name: str) -> TaintedValue | None:
        return self._env.get(name)

    def apply_sanitizers(self, tool_name: str, value: TaintedValue) -> TaintedValue:
        """Mark *value* sanitized for every rule this tool sanitizes."""
        out = value.copy()
        newly_sanitized: set[str] = set()
        for rule in self._rules:
            if tool_name in rule.sanitizers:
                out.sanitized_for.add(rule.name)
                newly_sanitized.add(rule.name)
        spec = self._specs.get(tool_name)
        if spec:
            for rule_name in spec.sanitizes:
                out.sanitized_for.add(rule_name)
                newly_sanitized.add(rule_name)
        digest = _content_digest(out.raw)
        if digest is not None:
            # Never refresh an older sanitizer's pin just because another
            # sanitizer ran later; that would launder mutations between steps.
            for rule_name in newly_sanitized:
                out.sanitized_digests[rule_name] = digest
        return out

    # -- sink checking ---------------------------------------------------

    def check_sink(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> GateDecision:
        """Evaluate taint rules for *tool_name*'s sink parameters.

        Fail-closed: a tool with no registered spec cannot be reasoned
        about, so any tainted value reaching it denies (Guardians'
        "missing spec" violation).
        """
        spec = self._specs.get(tool_name)
        relevant = [
            r
            for r in self._rules
            if r.sink_tool == tool_name or r.sink_tool == "*"
        ]
        if not relevant:
            return GateDecision(True, "no taint rules for tool", "taint")

        arg_env = {k: _unwrap(v) for k, v in arguments.items()}

        if spec is None:
            # No spec -> no taint labels -> can't reason about it.
            for val in find_tainted(arguments):
                if val.labels:
                    return GateDecision(
                        False,
                        f"tool '{tool_name}' has no taint spec; tainted value "
                        "reaches an unreasoned-about sink",
                        "taint",
                        {"rule": "missing_spec", "labels": sorted(val.labels)},
                    )
            return GateDecision(True, "no taint spec but no tainted input", "taint")

        sink_params = set(spec.sink_params)
        for rule in relevant:
            # Guardians expands sink_param="*" over the spec's declared
            # sink params; an explicit param name is checked as named.
            if rule.sink_param == "*":
                params = sorted(sink_params)
            else:
                params = [rule.sink_param]
            for param in params:
                if param not in arguments:
                    continue
                for val in find_tainted(arguments[param]):
                    if _taint_rule_fires(val, rule, arg_env, self._constants):
                        return GateDecision(
                            False,
                            f"tainted data from '{rule.source_tool}' flows to "
                            f"'{tool_name}.{param}'",
                            "taint",
                            {
                                "rule": rule.name,
                                "labels": sorted(val.labels),
                                "provenance": sorted(val.provenance),
                            },
                        )
        return GateDecision(True, "no taint rule fired", "taint")


# ---------------------------------------------------------------------------
# Security automata engine (port of _check_automata, runtime form)
# ---------------------------------------------------------------------------


class AutomatonEngine:
    """Nondeterministic security-automaton tracker over tool-call events.

    Each automaton holds a *set* of possible current states. On
    ``observe(tool_name, args)`` every transition matching
    ``(from_state, tool_name)`` whose condition holds fires; reaching any
    ``is_error`` state denies the call. Fail-closed exactly as in
    Guardians: an unparseable condition is assumed to fire, and a
    condition over unknown/symbolic argument values is assumed to fire.
    Once any automaton reaches an error state the session is violated and
    every later call is denied.
    """

    def __init__(self, automata: list[SecurityAutomaton] | None = None) -> None:
        self._automata = list(automata or [])
        if any(type(automaton) is not SecurityAutomaton for automaton in self._automata):
            raise ValueError("automata must contain only validated SecurityAutomaton values")
        names = [automaton.name for automaton in self._automata]
        if len(names) != len(set(names)):
            raise ValueError("automaton names must be unique")
        self._states: dict[str, set[str]] = {
            a.name: {a.initial_state} for a in self._automata
        }
        self._violated: dict[str, str] = {}  # automaton -> error state
        self._lock = threading.RLock()

    @property
    def violated(self) -> dict[str, str]:
        with self._lock:
            return dict(self._violated)

    def observe(self, tool_name: str, arguments: dict[str, Any]) -> GateDecision:
        with self._lock:
            return self._observe_locked(tool_name, arguments)

    def _observe_locked(self, tool_name: str, arguments: dict[str, Any]) -> GateDecision:
        """Advance automata on a tool-call event; deny on error states."""
        if self._violated:
            name = sorted(self._violated)[0]
            return GateDecision(
                False,
                f"security automaton '{name}' already in error state "
                f"'{self._violated[name]}'; session halted",
                "automaton",
                {"automaton": name, "error_state": self._violated[name]},
            )

        raw_args = {k: _unwrap(v) for k, v in arguments.items()}

        for automaton in self._automata:
            current_states = self._states[automaton.name]
            error_states = {s.name for s in automaton.states if s.is_error}
            next_states: set[str] = set()

            for current in sorted(current_states):
                fired = False
                for trans in automaton.transitions:
                    if trans.from_state != current or trans.tool_name != tool_name:
                        continue
                    if trans.condition:
                        eval_env: dict[str, Any] = {}
                        eval_env.update(raw_args)
                        eval_env.update(automaton.constants)
                        refs = expr_names(trans.condition)
                        if any(n not in eval_env for n in refs):
                            # Symbolic / unknown argument: assume it fires.
                            fires = True
                        else:
                            try:
                                fires = _eval_condition(trans.condition, eval_env)
                            except Exception:
                                fires = True  # fail closed
                        if not fires:
                            continue
                    if trans.to_state in error_states:
                        self._violated[automaton.name] = trans.to_state
                        self._states[automaton.name] = {trans.to_state}
                        return GateDecision(
                            False,
                            f"security automaton '{automaton.name}' reached "
                            f"error state '{trans.to_state}' on tool call "
                            f"'{tool_name}'",
                            "automaton",
                            {
                                "automaton": automaton.name,
                                "error_state": trans.to_state,
                                "from_state": current,
                            },
                        )
                    next_states.add(trans.to_state)
                    fired = True

                if not fired:
                    next_states.add(current)

            self._states[automaton.name] = next_states

        return GateDecision(True, "no automaton violation", "automaton")

    def states(self) -> dict[str, tuple[str, ...]]:
        with self._lock:
            return {k: tuple(sorted(v)) for k, v in self._states.items()}


# ---------------------------------------------------------------------------
# Per-tool budgets (port of WorkflowExecutor budgets, per-tool form)
# ---------------------------------------------------------------------------


class BudgetEnforcer:
    """Per-tool call-count caps. Exceeding the cap denies, fail-closed.

    Guardians' executor raises ``SecurityViolation`` when a budget is
    exceeded; here each tool gets its own cap (``{"send_email": 3}``).
    Malformed limits (non-int, ``True``/``False``, negative, or an
    explicitly-present ``None``) fail closed: the tool is denied rather
    than left unbounded. An *absent* key means "no cap". ``reserve()`` is
    the atomic pre-execution path; its token is committed with
    ``record(tool_name, token)`` or returned with ``release(token)``.
    """

    _ABSENT: Any = object()

    def __init__(self, limits: dict[str, int] | None = None) -> None:
        if limits is not None and type(limits) is not dict:
            raise ValueError("budget limits must be a plain dict")
        if limits is not None and any(type(name) is not str or not name or len(name) > 256 for name in limits):
            raise ValueError("budget tool names must be non-empty strings <= 256 characters")
        self._limits = dict(limits or {})
        self._used: dict[str, int] = {}
        self._pending: dict[str, str] = {}  # reservation token -> tool name
        self._pending_counts: dict[str, int] = {}
        self._lock = threading.RLock()

    def check(self, tool_name: str) -> GateDecision:
        with self._lock:
            return self._check_locked(tool_name)

    def _check_locked(self, tool_name: str) -> GateDecision:
        if type(tool_name) is not str or not tool_name or len(tool_name) > 256:
            return GateDecision(False, "invalid budget tool name; denying", "budget")
        limit = self._limits.get(tool_name, self._ABSENT)
        if limit is self._ABSENT:
            return GateDecision(True, "no budget limit for tool", "budget")
        # Fail closed on malformed limits: bool is an int subclass, reject it.
        if (
            type(limit) is not int
            or limit < 0
        ):
            return GateDecision(
                False,
                f"malformed budget limit for tool '{tool_name}'; denying",
                "budget",
                {"limit_type": type(limit).__name__},
            )
        used = self._used.get(tool_name, 0) + self._pending_counts.get(tool_name, 0)
        if used >= limit:
            return GateDecision(
                False,
                f"budget exceeded for tool '{tool_name}': {used} >= {limit}",
                "budget",
                {"used": used, "limit": limit},
            )
        return GateDecision(
            True, "within budget", "budget", {"used": used, "limit": limit}
        )

    def reserve(self, tool_name: str) -> GateDecision:
        """Atomically claim one capped call slot before execution."""
        with self._lock:
            decision = self._check_locked(tool_name)
            if not decision.allowed or tool_name not in self._limits:
                return decision
            token = uuid.uuid4().hex
            self._pending[token] = tool_name
            self._pending_counts[tool_name] = self._pending_counts.get(tool_name, 0) + 1
            return GateDecision(
                True, decision.reason, decision.check,
                {**decision.detail, "reserved": True}, budget_reservation=token,
            )

    def release(self, reservation: str) -> bool:
        """Return an uncommitted slot after a later gate rejects the call."""
        if type(reservation) is not str or len(reservation) != 32 or any(
            char not in "0123456789abcdef" for char in reservation
        ):
            return False
        with self._lock:
            tool_name = self._pending.pop(reservation, None)
            if tool_name is None:
                return False
            self._pending_counts[tool_name] -= 1
            if self._pending_counts[tool_name] == 0:
                del self._pending_counts[tool_name]
            return True

    def record(self, tool_name: str, reservation: str | None = None) -> None:
        """Commit an executed call; pass the gate's reservation token when present."""
        if type(tool_name) is not str or not tool_name or len(tool_name) > 256:
            raise ValueError("invalid budget tool name")
        if reservation is not None and (
            type(reservation) is not str or len(reservation) != 32
            or any(char not in "0123456789abcdef" for char in reservation)
        ):
            raise ValueError("invalid budget reservation token")
        with self._lock:
            if reservation is not None:
                reserved_tool = self._pending.get(reservation)
                if reserved_tool != tool_name:
                    raise ValueError("budget reservation is missing or belongs to another tool")
                self._pending.pop(reservation)
                self._pending_counts[tool_name] -= 1
                if self._pending_counts[tool_name] == 0:
                    del self._pending_counts[tool_name]
            else:
                if self._pending_counts.get(tool_name, 0):
                    raise ValueError("a reservation token is required while calls are reserved")
                decision = self._check_locked(tool_name)
                if not decision.allowed:
                    raise ValueError(decision.reason)
            self._used[tool_name] = self._used.get(tool_name, 0) + 1

    def usage(self) -> dict[str, int]:
        with self._lock:
            return dict(self._used)


# ---------------------------------------------------------------------------
# Combined gate
# ---------------------------------------------------------------------------


class ProvenanceTaintGate:
    """One gate composing budget → automaton → taint, first deny wins.

    Mirrors the order of Guardians' executor: preconditions/automata
    before the call, atomic budget reservation, then execution and taint
    wrapping. ``evaluate`` returns a reservation token for capped tools;
    after execution the caller passes it to ``budget.record``. If the call
    is abandoned, the caller releases it. Later gate denials release it
    automatically.
    """

    def __init__(
        self,
        tracker: TaintTracker,
        automata: AutomatonEngine | None = None,
        budgets: BudgetEnforcer | None = None,
    ) -> None:
        self.tracker = tracker
        self.automata = automata or AutomatonEngine()
        self.budgets = budgets or BudgetEnforcer()
        self._lock = threading.RLock()

    def evaluate(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> GateDecision:
        """Pre-call gate: budget, then automaton, then taint sinks."""
        with self._lock:
            decision = self.budgets.reserve(tool_name)
            if not decision.allowed:
                return decision
            reservation = decision.budget_reservation
            decision = self.automata.observe(tool_name, arguments)
            if not decision.allowed:
                if reservation:
                    self.budgets.release(reservation)
                return decision
            decision = self.tracker.check_sink(tool_name, arguments)
            if not decision.allowed:
                if reservation:
                    self.budgets.release(reservation)
                return decision
            return GateDecision(
                decision.allowed, decision.reason, decision.check, decision.detail,
                budget_reservation=reservation,
            )

    def produce_result(
        self, tool_name: str, raw_result: Any, arguments: dict[str, Any]
    ) -> TaintedValue:
        """Wrap a tool's result with taint metadata + sanitizer marking."""
        wrapped = self.tracker.derive(tool_name, raw_result, arguments)
        return self.tracker.apply_sanitizers(tool_name, wrapped)


# ---------------------------------------------------------------------------
# Audit anchoring
# ---------------------------------------------------------------------------


def gate_audit_event(
    decision: GateDecision,
    tool_name: str,
    call_id: str = "",
) -> dict[str, Any]:
    """Audit event for a gate decision (fits ``audit.ndjson/1`` payloads)."""
    return {
        "event": "provenance_taint.decision",
        "tool": tool_name,
        "call_id": call_id,
        "allowed": decision.allowed,
        "check": decision.check,
        "reason": decision.reason,
        "detail": dict(decision.detail),
    }


__all__ = [
    "AutomatonEngine",
    "AutomatonState",
    "AutomatonTransition",
    "BudgetEnforcer",
    "BudgetLimit",
    "GateDecision",
    "ProvenanceTaintGate",
    "SecurityAutomaton",
    "TaintRule",
    "TaintTracker",
    "TaintedValue",
    "ToolTaintSpec",
    "expr_names",
    "find_tainted",
    "gate_audit_event",
    "safe_eval",
]
