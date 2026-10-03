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
import operator
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# safe_eval: AST-allowlisted expression evaluator (port of safe_eval.py)
# ---------------------------------------------------------------------------

_CMP_OPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}


def safe_eval(expr: str, env: dict[str, Any]) -> Any:
    """Evaluate a simple expression safely against *env*.

    Raises :class:`ValueError` on anything outside the allowlist. Callers
    treat the raise as "condition fires" — fail-closed, exactly as in
    Guardians' ``_check_automata``.
    """
    tree = ast.parse(expr, mode="eval")
    return _eval_node(tree.body, env)


def _eval_node(node: ast.expr, env: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        try:
            return env[node.id]
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
                if current not in comp_val:
                    return False
            elif isinstance(op, ast.NotIn):
                if current in comp_val:
                    return False
            else:
                fn = _CMP_OPS.get(type(op))
                if fn is None:
                    raise ValueError(
                        f"disallowed comparison: {type(op).__name__}"
                    )
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
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
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

    def copy(self) -> "TaintedValue":
        return TaintedValue(
            raw=self.raw,
            labels=set(self.labels),
            provenance=set(self.provenance),
            source_tool=self.source_tool,
            sanitized_for=set(self.sanitized_for),
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
            if not safe_eval(rule.condition, eval_env):
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
        self._specs = dict(specs or {})
        self._rules = list(rules or [])
        self._constants = dict(constants or {})
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
        for rule in self._rules:
            if tool_name in rule.sanitizers:
                out.sanitized_for.add(rule.name)
        spec = self._specs.get(tool_name)
        if spec:
            for rule_name in spec.sanitizes:
                out.sanitized_for.add(rule_name)
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
    ``observe(tool_name, args)`` the first transition matching
    ``(from_state, tool_name)`` whose condition holds fires; reaching an
    ``is_error`` state denies the call. Fail-closed exactly as in
    Guardians: an unparseable condition is assumed to fire, and a
    condition over unknown/symbolic argument values is assumed to fire.
    Once any automaton reaches an error state the session is violated and
    every later call is denied.
    """

    def __init__(self, automata: list[SecurityAutomaton] | None = None) -> None:
        self._automata = list(automata or [])
        self._states: dict[str, set[str]] = {
            a.name: {a.initial_state} for a in self._automata
        }
        self._violated: dict[str, str] = {}  # automaton -> error state

    @property
    def violated(self) -> dict[str, str]:
        return dict(self._violated)

    def observe(self, tool_name: str, arguments: dict[str, Any]) -> GateDecision:
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
                transitioned = False
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
                                fires = bool(safe_eval(trans.condition, eval_env))
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
                    transitioned = True
                    break

                if not transitioned:
                    next_states.add(current)

            self._states[automaton.name] = next_states

        return GateDecision(True, "no automaton violation", "automaton")

    def states(self) -> dict[str, tuple[str, ...]]:
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
    than left unbounded. An *absent* key means "no cap".
    """

    _ABSENT: Any = object()

    def __init__(self, limits: dict[str, int] | None = None) -> None:
        self._limits = dict(limits or {})
        self._used: dict[str, int] = {}

    def check(self, tool_name: str) -> GateDecision:
        limit = self._limits.get(tool_name, self._ABSENT)
        if limit is self._ABSENT:
            return GateDecision(True, "no budget limit for tool", "budget")
        # Fail closed on malformed limits: bool is an int subclass, reject it.
        if (
            limit is None
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 0
        ):
            return GateDecision(
                False,
                f"malformed budget limit for tool '{tool_name}'; denying",
                "budget",
                {"limit": repr(limit)},
            )
        used = self._used.get(tool_name, 0)
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

    def record(self, tool_name: str) -> None:
        """Count one executed call. Called only after the gate allows."""
        self._used[tool_name] = self._used.get(tool_name, 0) + 1

    def usage(self) -> dict[str, int]:
        return dict(self._used)


# ---------------------------------------------------------------------------
# Combined gate
# ---------------------------------------------------------------------------


class ProvenanceTaintGate:
    """One gate composing budget → automaton → taint, first deny wins.

    Mirrors the order of Guardians' executor: preconditions/automata
    before the call, budget tick, then execution and taint wrapping.
    ``evaluate`` runs the pre-call checks; on allow, the caller executes
    the tool and feeds the raw result to ``produce_result`` for taint
    wrapping + sanitizer marking, then ``budget.record``.
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

    def evaluate(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> GateDecision:
        """Pre-call gate: budget, then automaton, then taint sinks."""
        decision = self.budgets.check(tool_name)
        if not decision.allowed:
            return decision
        decision = self.automata.observe(tool_name, arguments)
        if not decision.allowed:
            return decision
        return self.tracker.check_sink(tool_name, arguments)

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
