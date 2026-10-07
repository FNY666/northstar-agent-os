"""SMT solver interface: assert/check-sat over a finite-domain fragment.

Satisfiability Modulo Theories (SMT) is the workhorse behind bounded
model checking, configuration validation, and policy feasibility
analysis: the host *asserts* constraints as expressions, asks
*check-sat*, and either receives a *model* (a variable assignment that
satisfies every assertion) or a proof of unsatisfiability (an *unsat
core*).

This module pins the SMT-LIB interaction shape:

* ``assert_expr(expr)`` -- add a boolean-sorted constraint.
* ``check_sat()`` -- returns ``SatResult.SAT`` / ``UNSAT`` / ``UNKNOWN``.
* ``get_model()`` -- frozen variable assignment, valid only after SAT.
* ``unsat_core()`` -- minimal asserted-assertion subset that is still
  UNSAT (deletion-based minimization), valid only after UNSAT.
* ``push()`` / ``pop()`` -- incremental assertion stack.
* ``reset()`` -- clear everything.

The decision procedure is *genuine* for the finite-domain fragment:
every integer variable must be declared with finite bounds
(``IntVar(name, lo, hi)``); the solver enumerates the (deterministic,
name-sorted) assignment space and evaluates each assertion. For that
fragment the verdict is complete: SAT means a model exists and is
returned, UNSAT means no assignment satisfies the assertions. Problems
outside the fragment -- unbounded integer variables, or a domain
product larger than the ``max_evaluations`` guardrail -- answer
``UNKNOWN`` with a recorded reason (the SMT-LIB honest refusal), never
a guessed verdict.

Honest scope: this is an exhaustive finite-domain solver, not a
theory-combining DPLL(T) engine. Worst case is exponential in the
number of variables; it is the *bookkeeping and interface* half of an
SMT integration. Hosts with large or unbounded problems should bound
their variables or plug a real solver (Z3/CVC5) behind this API --
the call sites (assert/check/model/core) do not change. Deterministic
by design: same assertions, same model, same digest, no randomness,
no wall-clock. Integer arithmetic is exact (arbitrary precision);
there is no float anywhere, so the ``>2**53`` canonical-JSON caveat
from other modules does not apply here.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


#: Version pin for this module's record shape.
SMT_SOLVER_VERSION = "smt-solver.v1"

#: Schema pin carried on records and audit events.
SMT_SOLVER_SCHEMA = "northstar.smt-solver.v1"

#: Domain-separation prefix for digest pins.
_DOMAIN = b"northstar.smt-solver.v1:"

#: Default cap on the number of assignments enumerated by one check_sat.
_DEFAULT_MAX_EVALUATIONS = 1_048_576

#: Default cap on a single integer variable's domain width.
_DEFAULT_MAX_VAR_DOMAIN = 1_000_000


class SMTError(Exception):
    """Raised for malformed expressions or misuse of the solver API."""


class SatResult(enum.Enum):
    """The three SMT-LIB verdicts. UNKNOWN is a refusal, never a guess."""

    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Expression AST (frozen, fail-closed construction)
# ---------------------------------------------------------------------------


def _reject_bool_int(value: object, name: str) -> int:
    """Integer coercion that refuses bools (True == 1 would alias values)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SMTError(f"{name} must be an int, got {type(value).__name__}")
    return value


def _require_name(name: object) -> str:
    if isinstance(name, bool) or not isinstance(name, str) or not name:
        raise SMTError(f"variable name must be a non-empty str, got {name!r}")
    return name


class _Node:
    """Mixin: every expression node reports an SMT sort."""

    @property
    def sort(self) -> str:  # pragma: no cover - overridden everywhere
        raise NotImplementedError


def _need_int(node: object, ctx: str) -> _Node:
    # Sort-polymorphic: Ite carries .sort without inheriting the mixin.
    if not isinstance(node, _Node) or node.sort != "int":
        raise SMTError(f"{ctx}: expected int-sorted expression, got {type(node).__name__}")
    return node


def _need_bool(node: object, ctx: str) -> _Node:
    if not isinstance(node, _Node) or node.sort != "bool":
        raise SMTError(f"{ctx}: expected bool-sorted expression, got {type(node).__name__}")
    return node


class _IntNode(_Node):
    @property
    def sort(self) -> str:
        return "int"

    # Arithmetic sugar; == is deliberately NOT overloaded (dataclass
    # identity must stay intact) -- use Eq(a, b).
    def __add__(self, other: object) -> "Add":
        return Add((self, _need_int(other, "add")))

    def __radd__(self, other: object) -> "Add":
        return Add((_need_int(other, "add"), self))

    def __sub__(self, other: object) -> "Sub":
        return Sub(self, _need_int(other, "sub"))

    def __rsub__(self, other: object) -> "Sub":
        return Sub(_need_int(other, "sub"), self)

    def __mul__(self, other: object) -> "Mul":
        return Mul((self, _need_int(other, "mul")))

    def __rmul__(self, other: object) -> "Mul":
        return Mul((_need_int(other, "mul"), self))

    def __neg__(self) -> "Neg":
        return Neg(self)


class _BoolNode(_Node):
    @property
    def sort(self) -> str:
        return "bool"

    def __and__(self, other: object) -> "And":
        return And((_need_bool(self, "and"), _need_bool(other, "and")))

    def __or__(self, other: object) -> "Or":
        return Or((_need_bool(self, "or"), _need_bool(other, "or")))

    def __invert__(self) -> "Not":
        return Not(self)


@dataclass(frozen=True)
class IntConst(_IntNode):
    value: int

    def __post_init__(self) -> None:
        _reject_bool_int(self.value, "IntConst value")


@dataclass(frozen=True)
class BoolConst(_BoolNode):
    value: bool

    def __post_init__(self) -> None:
        if not isinstance(self.value, bool):
            raise SMTError(f"BoolConst value must be a bool, got {type(self.value).__name__}")


TRUE = BoolConst(True)
FALSE = BoolConst(False)


@dataclass(frozen=True)
class IntVar(_IntNode):
    name: str
    lo: Optional[int] = None
    hi: Optional[int] = None

    def __post_init__(self) -> None:
        _require_name(self.name)
        if self.lo is not None:
            _reject_bool_int(self.lo, "IntVar lo")
        if self.hi is not None:
            _reject_bool_int(self.hi, "IntVar hi")
        if (self.lo is None) != (self.hi is None):
            raise SMTError("IntVar bounds must be both set or both None")
        if self.lo is not None and self.lo > self.hi:  # type: ignore[operator]
            raise SMTError(f"IntVar lo ({self.lo}) > hi ({self.hi})")

    @property
    def bounded(self) -> bool:
        return self.lo is not None


@dataclass(frozen=True)
class BoolVar(_BoolNode):
    name: str

    def __post_init__(self) -> None:
        _require_name(self.name)


@dataclass(frozen=True)
class Add(_IntNode):
    args: Tuple[_IntNode, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.args, tuple) or len(self.args) < 2:
            raise SMTError("Add needs a tuple of >= 2 int expressions")
        for a in self.args:
            _need_int(a, "Add")


@dataclass(frozen=True)
class Mul(_IntNode):
    args: Tuple[_IntNode, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.args, tuple) or len(self.args) < 2:
            raise SMTError("Mul needs a tuple of >= 2 int expressions")
        for a in self.args:
            _need_int(a, "Mul")


@dataclass(frozen=True)
class Sub(_IntNode):
    left: _IntNode
    right: _IntNode

    def __post_init__(self) -> None:
        _need_int(self.left, "Sub")
        _need_int(self.right, "Sub")


@dataclass(frozen=True)
class Neg(_IntNode):
    arg: _IntNode

    def __post_init__(self) -> None:
        _need_int(self.arg, "Neg")


def _check_cmp(left: object, right: object, ctx: str) -> Tuple[_IntNode, _IntNode]:
    return _need_int(left, ctx), _need_int(right, ctx)


@dataclass(frozen=True)
class Eq(_BoolNode):
    left: _IntNode
    right: _IntNode

    def __post_init__(self) -> None:
        _check_cmp(self.left, self.right, "Eq")


@dataclass(frozen=True)
class Ne(_BoolNode):
    left: _IntNode
    right: _IntNode

    def __post_init__(self) -> None:
        _check_cmp(self.left, self.right, "Ne")


@dataclass(frozen=True)
class Lt(_BoolNode):
    left: _IntNode
    right: _IntNode

    def __post_init__(self) -> None:
        _check_cmp(self.left, self.right, "Lt")


@dataclass(frozen=True)
class Le(_BoolNode):
    left: _IntNode
    right: _IntNode

    def __post_init__(self) -> None:
        _check_cmp(self.left, self.right, "Le")


@dataclass(frozen=True)
class Gt(_BoolNode):
    left: _IntNode
    right: _IntNode

    def __post_init__(self) -> None:
        _check_cmp(self.left, self.right, "Gt")


@dataclass(frozen=True)
class Ge(_BoolNode):
    left: _IntNode
    right: _IntNode

    def __post_init__(self) -> None:
        _check_cmp(self.left, self.right, "Ge")


@dataclass(frozen=True)
class And(_BoolNode):
    args: Tuple[_BoolNode, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.args, tuple) or len(self.args) < 1:
            raise SMTError("And needs a tuple of >= 1 bool expressions")
        for a in self.args:
            _need_bool(a, "And")


@dataclass(frozen=True)
class Or(_BoolNode):
    args: Tuple[_BoolNode, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.args, tuple) or len(self.args) < 1:
            raise SMTError("Or needs a tuple of >= 1 bool expressions")
        for a in self.args:
            _need_bool(a, "Or")


@dataclass(frozen=True)
class Not(_BoolNode):
    arg: _BoolNode

    def __post_init__(self) -> None:
        _need_bool(self.arg, "Not")


@dataclass(frozen=True)
class Implies(_BoolNode):
    antecedent: _BoolNode
    consequent: _BoolNode

    def __post_init__(self) -> None:
        _need_bool(self.antecedent, "Implies")
        _need_bool(self.consequent, "Implies")


@dataclass(frozen=True)
class Ite(_Node):
    """If-then-else; both branches must share one sort."""

    cond: _BoolNode
    then_branch: _Node
    else_branch: _Node

    def __post_init__(self) -> None:
        _need_bool(self.cond, "Ite")
        if not isinstance(self.then_branch, _Node) or not isinstance(
            self.else_branch, _Node
        ):
            raise SMTError("Ite branches must be expressions")
        if self.then_branch.sort != self.else_branch.sort:
            raise SMTError(
                "Ite branches must share a sort: "
                f"{self.then_branch.sort} vs {self.else_branch.sort}"
            )

    @property
    def sort(self) -> str:
        return self.then_branch.sort


# ---------------------------------------------------------------------------
# Canonical serialization (deterministic digest pins)
# ---------------------------------------------------------------------------


def _canonical(node: _Node) -> tuple:
    if isinstance(node, IntConst):
        return ("int-const", node.value)
    if isinstance(node, BoolConst):
        return ("bool-const", node.value)
    if isinstance(node, IntVar):
        return ("int-var", node.name, node.lo, node.hi)
    if isinstance(node, BoolVar):
        return ("bool-var", node.name)
    if isinstance(node, (Add, Mul)):
        tag = "add" if isinstance(node, Add) else "mul"
        return (tag,) + tuple(_canonical(a) for a in node.args)
    if isinstance(node, Sub):
        return ("sub", _canonical(node.left), _canonical(node.right))
    if isinstance(node, Neg):
        return ("neg", _canonical(node.arg))
    if isinstance(node, (Eq, Ne, Lt, Le, Gt, Ge)):
        tag = {
            Eq: "eq",
            Ne: "ne",
            Lt: "lt",
            Le: "le",
            Gt: "gt",
            Ge: "ge",
        }[type(node)]
        return (tag, _canonical(node.left), _canonical(node.right))
    if isinstance(node, (And, Or)):
        tag = "and" if isinstance(node, And) else "or"
        return (tag,) + tuple(_canonical(a) for a in node.args)
    if isinstance(node, Not):
        return ("not", _canonical(node.arg))
    if isinstance(node, Implies):
        return ("implies", _canonical(node.antecedent), _canonical(node.consequent))
    if isinstance(node, Ite):
        return (
            "ite",
            _canonical(node.cond),
            _canonical(node.then_branch),
            _canonical(node.else_branch),
        )
    raise SMTError(f"cannot canonicalize {type(node).__name__}")


def _ser(value: object) -> str:
    """Deterministic serializer: ints exact, bools tagged, no floats."""
    if isinstance(value, bool):
        return "b1" if value else "b0"
    if isinstance(value, int):
        return "i" + str(value)
    if isinstance(value, str):
        return "s" + str(len(value)) + ":" + value
    if value is None:
        return "n"
    if isinstance(value, tuple):
        return "t" + str(len(value)) + "[" + ",".join(_ser(v) for v in value) + "]"
    raise SMTError(f"cannot serialize {type(value).__name__}")


def _sha256_pin(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(_DOMAIN + data).hexdigest()


# ---------------------------------------------------------------------------
# Evaluation over a concrete assignment
# ---------------------------------------------------------------------------

_Env = Dict[str, object]


def _walk_vars(node: _Node, out: Dict[str, _Node]) -> None:
    """Collect variable nodes by name (first occurrence wins)."""
    if isinstance(node, (IntVar, BoolVar)):
        out.setdefault(node.name, node)
        return
    if isinstance(node, (IntConst, BoolConst)):
        return
    if isinstance(node, (Add, Mul, And, Or)):
        for a in node.args:
            _walk_vars(a, out)
    elif isinstance(node, (Sub, Eq, Ne, Lt, Le, Gt, Ge)):
        _walk_vars(node.left, out)
        _walk_vars(node.right, out)
    elif isinstance(node, Neg):
        _walk_vars(node.arg, out)
    elif isinstance(node, Not):
        _walk_vars(node.arg, out)
    elif isinstance(node, Implies):
        _walk_vars(node.antecedent, out)
        _walk_vars(node.consequent, out)
    elif isinstance(node, Ite):
        _walk_vars(node.cond, out)
        _walk_vars(node.then_branch, out)
        _walk_vars(node.else_branch, out)
    else:  # pragma: no cover - all node types handled above
        raise SMTError(f"unknown node {type(node).__name__}")


def _eval(node: _Node, env: _Env) -> object:
    if isinstance(node, IntConst):
        return node.value
    if isinstance(node, BoolConst):
        return node.value
    if isinstance(node, (IntVar, BoolVar)):
        return env[node.name]
    if isinstance(node, Add):
        total = 0
        for a in node.args:
            total += _eval(a, env)  # type: ignore[operator]
        return total
    if isinstance(node, Mul):
        prod = 1
        for a in node.args:
            prod *= _eval(a, env)  # type: ignore[operator]
        return prod
    if isinstance(node, Sub):
        return _eval(node.left, env) - _eval(node.right, env)  # type: ignore[operator]
    if isinstance(node, Neg):
        return -_eval(node.arg, env)  # type: ignore[operator]
    if isinstance(node, Eq):
        return _eval(node.left, env) == _eval(node.right, env)
    if isinstance(node, Ne):
        return _eval(node.left, env) != _eval(node.right, env)
    if isinstance(node, Lt):
        return _eval(node.left, env) < _eval(node.right, env)  # type: ignore[operator]
    if isinstance(node, Le):
        return _eval(node.left, env) <= _eval(node.right, env)  # type: ignore[operator]
    if isinstance(node, Gt):
        return _eval(node.left, env) > _eval(node.right, env)  # type: ignore[operator]
    if isinstance(node, Ge):
        return _eval(node.left, env) >= _eval(node.right, env)  # type: ignore[operator]
    if isinstance(node, And):
        return all(_eval(a, env) for a in node.args)
    if isinstance(node, Or):
        return any(_eval(a, env) for a in node.args)
    if isinstance(node, Not):
        return not _eval(node.arg, env)
    if isinstance(node, Implies):
        return (not _eval(node.antecedent, env)) or _eval(node.consequent, env)
    if isinstance(node, Ite):
        branch = node.then_branch if _eval(node.cond, env) else node.else_branch
        return _eval(branch, env)
    raise SMTError(f"cannot evaluate {type(node).__name__}")  # pragma: no cover


# ---------------------------------------------------------------------------
# Model record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Model:
    """A satisfying assignment: frozen, name-sorted ``(name, value)`` pairs."""

    bindings: Tuple[Tuple[str, object], ...]
    version: str = SMT_SOLVER_VERSION
    schema: str = SMT_SOLVER_SCHEMA

    def __post_init__(self) -> None:
        if not isinstance(self.bindings, tuple):
            raise SMTError("Model bindings must be a tuple")
        names = [n for n, _ in self.bindings]
        if names != sorted(names):
            raise SMTError("Model bindings must be name-sorted")
        if len(set(names)) != len(names):
            raise SMTError("Model bindings must have unique names")
        for name, value in self.bindings:
            if isinstance(name, bool) or not isinstance(name, str):
                raise SMTError("Model binding name must be a str")
            if isinstance(value, bool):
                continue
            if not isinstance(value, int):
                raise SMTError("Model binding value must be int or bool")
        if self.version != SMT_SOLVER_VERSION:
            raise SMTError("bad version pin")
        if self.schema != SMT_SOLVER_SCHEMA:
            raise SMTError("bad schema pin")

    def lookup(self, name: str) -> object:
        for n, v in self.bindings:
            if n == name:
                return v
        raise SMTError(f"variable {name!r} not in model")

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "version": self.version,
            "bindings": {n: v for n, v in self.bindings},
        }


# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------


class SMTSolver:
    """Incremental SMT solver over the finite-domain fragment.

    Usage::

        s = SMTSolver()
        x = IntVar("x", 0, 3)
        y = IntVar("y", 0, 3)
        s.assert_expr(Eq(Add((x, y)), IntConst(4)))
        s.assert_expr(Lt(x, y))
        assert s.check_sat() is SatResult.SAT
        model = s.get_model()  # x=1, y=3 (deterministic first model)

    All methods are deterministic; the solver holds no randomness and
    reads no clock. Assertion indices returned by ``assert_expr`` are
    stable within the current stack level and are what ``unsat_core``
    reports.
    """

    def __init__(
        self,
        *,
        max_evaluations: int = _DEFAULT_MAX_EVALUATIONS,
        max_var_domain: int = _DEFAULT_MAX_VAR_DOMAIN,
    ) -> None:
        if isinstance(max_evaluations, bool) or not isinstance(max_evaluations, int):
            raise SMTError("max_evaluations must be an int")
        if isinstance(max_var_domain, bool) or not isinstance(max_var_domain, int):
            raise SMTError("max_var_domain must be an int")
        if max_evaluations < 1 or max_var_domain < 1:
            raise SMTError("guardrails must be >= 1")
        self._max_evaluations = max_evaluations
        self._max_var_domain = max_var_domain
        self._stack: List[List[_BoolNode]] = [[]]
        self._last_result: Optional[SatResult] = None
        self._last_model: Optional[Model] = None
        self._last_core: Optional[Tuple[int, ...]] = None
        self._unknown_reason: Optional[str] = None
        self._checks = 0
        self._evaluations = 0
        self._last_evaluations = 0

    # -- assertions ------------------------------------------------------

    def assert_expr(self, expr: object) -> int:
        """Assert a bool-sorted constraint; returns its assertion index."""
        node = _need_bool(expr, "assert_expr")
        self._stack[-1].append(node)
        self._invalidate()
        return len(self._stack[-1]) - 1

    def assertions(self) -> Tuple[_BoolNode, ...]:
        """Current assertion stack level as a tuple (read-only view)."""
        return tuple(self._stack[-1])

    def push(self) -> None:
        """Open a new assertion scope (copies the current level)."""
        self._stack.append(list(self._stack[-1]))
        self._invalidate()

    def pop(self) -> None:
        """Close the current scope, discarding assertions made inside it."""
        if len(self._stack) == 1:
            raise SMTError("pop with no matching push")
        self._stack.pop()
        self._invalidate()

    def reset(self) -> None:
        """Drop all assertions and all cached results."""
        self._stack = [[]]
        self._invalidate()
        self._checks = 0
        self._evaluations = 0
        self._last_evaluations = 0

    def _invalidate(self) -> None:
        self._last_result = None
        self._last_model = None
        self._last_core = None
        self._unknown_reason = None

    # -- solving ----------------------------------------------------------

    def _domains(
        self, variables: Dict[str, _Node]
    ) -> Optional[Tuple[List[str], List[tuple]]]:
        """Ordered (names, domains); None when outside the decidable fragment."""
        names = sorted(variables)
        domains: List[tuple] = []
        product = 1
        for name in names:
            var = variables[name]
            if isinstance(var, BoolVar):
                domains.append((False, True))
                product *= 2
            elif isinstance(var, IntVar):
                if not var.bounded:
                    self._unknown_reason = (
                        f"unbounded integer variable {name!r}: "
                        "declare IntVar with lo/hi to stay in the decidable fragment"
                    )
                    return None
                width = var.hi - var.lo + 1  # type: ignore[operator]
                if width > self._max_var_domain:
                    self._unknown_reason = (
                        f"variable {name!r} domain width {width} exceeds "
                        f"max_var_domain {self._max_var_domain}"
                    )
                    return None
                domains.append(tuple(range(var.lo, var.hi + 1)))  # type: ignore[operator]
                product *= width
            else:  # pragma: no cover - walk only yields vars
                raise SMTError(f"unknown variable node {type(var).__name__}")
            if product > self._max_evaluations:
                self._unknown_reason = (
                    f"domain product exceeds max_evaluations "
                    f"({self._max_evaluations})"
                )
                return None
        return names, domains

    def _search(
        self, assertions: List[_BoolNode]
    ) -> Tuple[Optional[_Env], bool, int]:
        """Exhaustive search. Returns (model_env|None, decided, evaluations).

        ``decided`` is False when the problem is outside the fragment
        (then the unknown reason is already recorded).
        """
        variables: Dict[str, _Node] = {}
        for a in assertions:
            _walk_vars(a, variables)
        dom = self._domains(variables)
        if dom is None:
            return None, False, 0
        names, domains = dom
        evaluations = 0
        # Iterative odometer over the cartesian product; names sorted so
        # the first model found is deterministic across runs.
        indices = [0] * len(names)
        while True:
            env: _Env = {names[i]: domains[i][indices[i]] for i in range(len(names))}
            evaluations += 1
            if all(_eval(a, env) for a in assertions):
                return env, True, evaluations
            # advance odometer
            pos = len(names) - 1
            while pos >= 0:
                indices[pos] += 1
                if indices[pos] < len(domains[pos]):
                    break
                indices[pos] = 0
                pos -= 1
            if pos < 0:
                return None, True, evaluations

    def check_sat(self) -> SatResult:
        """Decide the current assertions: SAT, UNSAT, or UNKNOWN."""
        self._checks += 1
        self._last_model = None
        self._last_core = None
        self._unknown_reason = None
        env, decided, evaluations = self._search(self._stack[-1])
        self._evaluations += evaluations
        self._last_evaluations = evaluations
        if not decided:
            self._last_result = SatResult.UNKNOWN
            return SatResult.UNKNOWN
        if env is not None:
            bindings = tuple(sorted((n, env[n]) for n in env))
            self._last_model = Model(bindings=bindings)
            self._last_result = SatResult.SAT
            return SatResult.SAT
        self._last_result = SatResult.UNSAT
        return SatResult.UNSAT

    def get_model(self) -> Model:
        """The satisfying assignment from the last ``check_sat``.

        Valid only when the last verdict was SAT; anything else is a
        fail-closed ``SMTError`` (a stale or absent model is never
        handed out silently).
        """
        if self._last_result is not SatResult.SAT or self._last_model is None:
            raise SMTError(
                "get_model requires a SAT verdict from the current assertions; "
                f"last result was {self._last_result}"
            )
        return self._last_model

    def unsat_core(self) -> Tuple[int, ...]:
        """Minimal (deletion-based) subset of assertion indices still UNSAT.

        Valid only when the last verdict was UNSAT. The core is *minimal*:
        removing any one of its assertions makes the remainder SAT. It is
        not guaranteed *minimum* (smallest possible).
        """
        if self._last_result is not SatResult.UNSAT:
            raise SMTError(
                "unsat_core requires an UNSAT verdict from the current assertions; "
                f"last result was {self._last_result}"
            )
        if self._last_core is not None:
            return self._last_core
        core = list(range(len(self._stack[-1])))
        changed = True
        while changed:
            changed = False
            for i in list(core):
                trial = [self._stack[-1][j] for j in core if j != i]
                env, decided, _ = self._search(trial)
                if decided and env is None:
                    core.remove(i)
                    changed = True
        self._last_core = tuple(core)
        return self._last_core

    def last_unknown_reason(self) -> Optional[str]:
        """Why the last ``check_sat`` answered UNKNOWN (None otherwise)."""
        return self._unknown_reason

    def stats(self) -> dict:
        """Solver bookkeeping: assertions, checks, evaluation counts."""
        return {
            "assertions": len(self._stack[-1]),
            "stack_depth": len(self._stack),
            "checks": self._checks,
            "evaluations_total": self._evaluations,
            "evaluations_last_check": self._last_evaluations,
            "max_evaluations": self._max_evaluations,
            "max_var_domain": self._max_var_domain,
        }

    def assertions_digest(self) -> str:
        """``sha256:`` pin over the canonical current assertion set."""
        canon = tuple(_canonical(a) for a in self._stack[-1])
        return _sha256_pin(_ser(canon).encode("utf-8"))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

#: Fixed vocabulary for :func:`smt_solver_audit_event`.
_AUDIT_KINDS = ("asserted", "checked", "pushed", "popped", "reset")


def smt_solver_audit_event(
    kind: str,
    solver: SMTSolver,
    seq: int,
    *,
    result: Optional[SatResult] = None,
) -> dict:
    """Shape an ``audit.ndjson/1`` record for a solver operation.

    ``checked`` events carry the verdict; other kinds carry the
    assertion digest so a verifier can confirm *which* constraints were
    live. Expression bodies are never logged, only the digest pin.
    """
    if kind not in _AUDIT_KINDS:
        raise SMTError(f"unknown audit kind: {kind!r}")
    if not isinstance(solver, SMTSolver):
        raise SMTError("solver must be an SMTSolver")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SMTError("seq must be a non-negative int")
    if kind == "checked":
        if not isinstance(result, SatResult):
            raise SMTError("checked events require a SatResult")
    elif result is not None:
        raise SMTError("result is only valid for checked events")
    record = {
        "schema": SMT_SOLVER_SCHEMA,
        "kind": kind,
        "seq": seq,
        "assertions": len(solver.assertions()),
        "assertions_digest": solver.assertions_digest(),
        "version": SMT_SOLVER_VERSION,
    }
    if result is not None:
        record["result"] = result.value
        if result is SatResult.UNKNOWN:
            record["unknown_reason"] = solver.last_unknown_reason()
    return record


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def _self_check() -> None:
    s = SMTSolver()
    x = IntVar("x", 0, 3)
    y = IntVar("y", 0, 3)
    s.assert_expr(Eq(Add((x, y)), IntConst(4)))
    s.assert_expr(Lt(x, y))
    assert s.check_sat() is SatResult.SAT
    model = s.get_model()
    assert model.lookup("x") == 1 and model.lookup("y") == 3, model.as_dict()
    # Push a contradiction: unsat, with a minimal core of the two asserts.
    s.push()
    s.assert_expr(Eq(x, IntConst(3)))
    assert s.check_sat() is SatResult.UNSAT
    core = s.unsat_core()
    assert len(core) == 2, core  # x+y==4, x<y, x==3 with x in [0,3]: minimal
    s.pop()
    assert s.check_sat() is SatResult.SAT
    # Unbounded variable: honest UNKNOWN, never a guess.
    s2 = SMTSolver()
    z = IntVar("z")
    s2.assert_expr(Eq(z, IntConst(1)))
    assert s2.check_sat() is SatResult.UNKNOWN
    assert s2.last_unknown_reason() is not None
    print("smt-solver OK: sat, model, unsat-core, push/pop, unknown-refusal")


def main() -> None:
    _self_check()


if __name__ == "__main__":
    main()
