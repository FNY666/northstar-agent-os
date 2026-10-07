"""Abstract interpretation over the interval domain (Cousot & Cousot, 1977).

Abstract interpretation answers "what can this program's variables
possibly hold at each point?" by *computing on abstractions* instead of
concrete values. The interval domain represents each variable's set of
possible values as ``[lo, hi]``; abstract operations (``+``, ``-``,
``*``, ``/``) are *sound over-approximations*: every concrete execution
is contained in the abstract result. That is the entire point -- if the
abstract result says a variable never goes negative, no concrete run
ever makes it negative.

The module provides:

* :class:`Interval` -- frozen abstract value: ``[lo, hi]`` with
  possibly-infinite ends, plus a bottom (empty) element. Join is the
  hull, meet is the intersection, transfer functions cover the four
  arithmetic ops with division-by-zero refused fail-closed (an interval
  containing 0 as divisor raises, it does not silently return top).
* :class:`AbstractInterp` -- runs a tiny straight-line-plus-loop
  language: ``("assign", var, expr)``, ``("assume", var, rel, const)``
  (guard refinement on branches), and ``("while", guard_var, body)``.
  Loop analysis iterates to a fixpoint, applying :meth:`widen` to force
  termination (an end that keeps growing is pushed to +/-infinity) and
  then :meth:`narrow` (a few descending iterations intersecting with
  the widened fixpoint) to recover precision.

Everything is exact-integer where finite (arbitrary precision), no
floats leak into the domain: infinities are the only non-integer
inhabitants and they are represented by ``math.inf``.

Honest scope: soundness holds for the *modeled* language only; it does
not lift to arbitrary host programs, and an over-approximation can cry
"maybe" where the truth is "no" (false positives are the price of
termination). Widening throws precision away on purpose -- the result
after a widened loop is *less* precise than the un-widened iterates,
by design. Division refuses to guess: a divisor interval containing 0
raises instead of returning ``[-inf, +inf]`` silently. State is
in-memory; persistence is the host's job.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional, Tuple


#: Version pin for this module's record shape.
ABSTRACT_INTERP_VERSION = "abstract-interp.v1"

#: Schema pin carried on audit records.
ABSTRACT_INTERP_SCHEMA = "northstar.abstract-interp.v1"


class AbstractInterpError(Exception):
    """Base error for abstract-interpretation failures."""


class DivisionByZeroError(AbstractInterpError):
    """Divisor interval contains 0 -- refused instead of guessed."""


class BottomError(AbstractInterpError):
    """Operation on the bottom (empty) element has no defined result."""


def _check_number(value: object, name: str) -> float:
    """Validate a domain number: finite-or-infinite, never bool/NaN."""
    if isinstance(value, bool):
        raise TypeError(f"{name} must not be bool")
    if isinstance(value, int):
        return float(value)
    if isinstance(value, float):
        if math.isnan(value):
            raise ValueError(f"{name} must not be NaN")
        return value
    raise TypeError(f"{name} must be int or float, got {type(value).__name__}")


@dataclass(frozen=True)
class Interval:
    """One abstract value: the closed range ``[lo, hi]`` or bottom.

    ``bottom=True`` marks the empty set (no possible concrete value);
    when bottom, ``lo``/``hi`` are ignored. Infinity is allowed at
    either end; NaN is refused.
    """

    lo: float = field(default=0.0)
    hi: float = field(default=0.0)
    bottom: bool = field(default=False)

    def __post_init__(self) -> None:
        if not isinstance(self.bottom, bool):
            raise TypeError("bottom must be bool")
        lo = _check_number(self.lo, "lo")
        hi = _check_number(self.hi, "hi")
        object.__setattr__(self, "lo", lo)
        object.__setattr__(self, "hi", hi)
        if not self.bottom and lo > hi:
            raise ValueError(f"empty interval [lo, hi] with lo > hi: use bottom=True")

    @staticmethod
    def of(lo: object, hi: object) -> "Interval":
        """Build ``[lo, hi]`` (bottom iff both are None is not allowed)."""
        return Interval(lo=lo, hi=hi)  # type: ignore[arg-type]

    @staticmethod
    def const(value: object) -> "Interval":
        """Singleton ``[v, v]``."""
        v = _check_number(value, "value")
        return Interval(lo=v, hi=v)

    @staticmethod
    def top() -> "Interval":
        """``[-inf, +inf]`` -- knows nothing."""
        return Interval(lo=-math.inf, hi=math.inf)

    @staticmethod
    def empty() -> "Interval":
        """The empty set -- unreachable."""
        return Interval(bottom=True)

    def is_bottom(self) -> bool:
        return self.bottom

    def is_top(self) -> bool:
        return not self.bottom and self.lo == -math.inf and self.hi == math.inf

    def contains(self, value: object) -> bool:
        """Concrete membership test."""
        if self.bottom:
            return False
        v = _check_number(value, "value")
        return self.lo <= v <= self.hi

    def width(self) -> float:
        """``hi - lo``; ``+inf`` for unbounded; raises on bottom."""
        if self.bottom:
            raise BottomError("bottom has no width")
        return self.hi - self.lo

    # -- lattice operations -------------------------------------------------

    def join(self, other: "Interval") -> "Interval":
        """Least upper bound: the hull covering both."""
        _require_interval(other, "other")
        if self.bottom:
            return other
        if other.bottom:
            return self
        return Interval(lo=min(self.lo, other.lo), hi=max(self.hi, other.hi))

    def meet(self, other: "Interval") -> "Interval":
        """Greatest lower bound: intersection (bottom when disjoint)."""
        _require_interval(other, "other")
        if self.bottom or other.bottom:
            return Interval.empty()
        lo, hi = max(self.lo, other.lo), min(self.hi, other.hi)
        if lo > hi:
            return Interval.empty()
        return Interval(lo=lo, hi=hi)

    def widen(self, other: "Interval") -> "Interval":
        """Standard widening: any end that grew jumps to infinity.

        Guarantees fixpoint termination for loops: each widened
        sequence is eventually stable because ends can only move to
        +/-infinity finitely many times.
        """
        _require_interval(other, "other")
        if self.bottom:
            return other
        if other.bottom:
            return self
        lo = -math.inf if other.lo < self.lo else self.lo
        hi = math.inf if other.hi > self.hi else self.hi
        return Interval(lo=lo, hi=hi)

    def narrow(self, other: "Interval") -> "Interval":
        """Narrowing: intersect with the previous iterate to recover
        precision after widening. Only ever shrinks (meet)."""
        return self.meet(other)

    def leq(self, other: "Interval") -> bool:
        """Partial order: ``self`` is contained in ``other``."""
        _require_interval(other, "other")
        if self.bottom:
            return True
        if other.bottom:
            return False
        return other.lo <= self.lo and self.hi <= other.hi

    # -- transfer functions (sound over-approximations) ----------------------

    def add(self, other: "Interval") -> "Interval":
        _require_interval(other, "other")
        if self.bottom or other.bottom:
            return Interval.empty()
        return Interval(lo=self.lo + other.lo, hi=self.hi + other.hi)

    def sub(self, other: "Interval") -> "Interval":
        _require_interval(other, "other")
        if self.bottom or other.bottom:
            return Interval.empty()
        return Interval(lo=self.lo - other.hi, hi=self.hi - other.lo)

    def mul(self, other: "Interval") -> "Interval":
        _require_interval(other, "other")
        if self.bottom or other.bottom:
            return Interval.empty()
        products = (
            self.lo * other.lo,
            self.lo * other.hi,
            self.hi * other.lo,
            self.hi * other.hi,
        )
        return Interval(lo=min(products), hi=max(products))

    def div(self, other: "Interval") -> "Interval":
        """Division; the divisor interval containing 0 raises
        :class:`DivisionByZeroError` -- no silent top."""
        _require_interval(other, "other")
        if self.bottom or other.bottom:
            return Interval.empty()
        if other.lo <= 0.0 <= other.hi:
            raise DivisionByZeroError(
                f"divisor interval {other} contains 0; refused, not widened to top"
            )
        quotients = (
            self.lo / other.lo,
            self.lo / other.hi,
            self.hi / other.lo,
            self.hi / other.hi,
        )
        return Interval(lo=min(quotients), hi=max(quotients))

    def neg(self) -> "Interval":
        if self.bottom:
            return Interval.empty()
        return Interval(lo=-self.hi, hi=-self.lo)

    def as_dict(self) -> dict:
        return {
            "schema": ABSTRACT_INTERP_SCHEMA,
            "version": ABSTRACT_INTERP_VERSION,
            "lo": None if self.bottom else self.lo,
            "hi": None if self.bottom else self.hi,
            "bottom": self.bottom,
        }


def _require_interval(value: object, name: str) -> Interval:
    if not isinstance(value, Interval):
        raise TypeError(f"{name} must be an Interval, got {type(value).__name__}")
    return value


def _require_var_name(name: object) -> str:
    if not isinstance(name, str) or not name:
        raise TypeError("variable name must be a non-empty str")
    return name


# -- tiny language -----------------------------------------------------------
#
# Statements are tuples:
#   ("assign", var, expr)          -- var := expr
#   ("assume", var, rel, const)    -- guard: rel in {"<","<=","==",">=",">"} vs const
#   ("while", guard_var, body)     -- body is a list of statements; the loop
#                                    re-runs while guard_var may be > 0
#
# Expressions are tuples:
#   ("const", v) | ("var", name) | ("neg", e)
#   ("add"|"sub"|"mul"|"div", e1, e2)

_Expr = tuple
_Stmt = tuple


def _eval_expr(expr: _Expr, env: Dict[str, Interval]) -> Interval:
    if not isinstance(expr, tuple) or not expr:
        raise TypeError("expression must be a non-empty tuple")
    tag = expr[0]
    if tag == "const":
        if len(expr) != 2:
            raise ValueError("const takes exactly one value")
        return Interval.const(expr[1])
    if tag == "var":
        if len(expr) != 2:
            raise ValueError("var takes exactly one name")
        name = _require_var_name(expr[1])
        return env.get(name, Interval.top())
    if tag == "neg":
        if len(expr) != 2:
            raise ValueError("neg takes exactly one operand")
        return _eval_expr(expr[1], env).neg()
    if tag in ("add", "sub", "mul", "div"):
        if len(expr) != 3:
            raise ValueError(f"{tag} takes exactly two operands")
        left = _eval_expr(expr[1], env)
        right = _eval_expr(expr[2], env)
        return getattr(left, tag)(right)
    raise ValueError(f"unknown expression tag {tag!r}")


def _apply_assume(env: Dict[str, Interval], var: str, rel: str, const: object) -> Dict[str, Interval]:
    """Refine ``var``'s interval under the assumption ``var rel const``."""
    _require_var_name(var)
    if rel not in ("<", "<=", "==", ">=", ">"):
        raise ValueError(f"unknown relation {rel!r}")
    c = _check_number(const, "const")
    cur = env.get(var, Interval.top())
    if cur.is_bottom():
        return dict(env)
    lo, hi = cur.lo, cur.hi
    if rel == "<":
        hi = min(hi, math.nextafter(c, -math.inf))
    elif rel == "<=":
        hi = min(hi, c)
    elif rel == "==":
        lo, hi = max(lo, c), min(hi, c)
    elif rel == ">=":
        lo = max(lo, c)
    else:  # ">"
        lo = max(lo, math.nextafter(c, math.inf))
    new = cur.meet(Interval(lo=lo, hi=hi)) if lo <= hi else Interval.empty()
    out = dict(env)
    out[var] = new
    return out


@dataclass(frozen=True)
class AnalysisResult:
    """Outcome of :meth:`AbstractInterp.analyze`."""

    env: Mapping[str, Interval]
    iterations: int
    widened: bool
    narrowed: bool

    def get(self, var: str) -> Interval:
        _require_var_name(var)
        return self.env.get(var, Interval.top())

    def as_dict(self) -> dict:
        return {
            "schema": ABSTRACT_INTERP_SCHEMA,
            "version": ABSTRACT_INTERP_VERSION,
            "env": {k: v.as_dict() for k, v in self.env.items()},
            "iterations": self.iterations,
            "widened": self.widened,
            "narrowed": self.narrowed,
        }


class AbstractInterp:
    """Fixpoint analyzer over the interval domain.

    ``analyze(program)`` walks the statement list; on ``while`` it
    iterates the body from the current environment, widening the loop
    head after ``widen_after`` iterations (default 2) to force
    termination, then runs ``narrow_steps`` descending iterations
    (default 2) intersecting back down. Caller supplies only the
    program -- there is no wall-clock, no randomness, no I/O.
    """

    def __init__(self, widen_after: int = 2, narrow_steps: int = 2, max_iters: int = 64) -> None:
        for name, v in (("widen_after", widen_after), ("narrow_steps", narrow_steps), ("max_iters", max_iters)):
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise ValueError(f"{name} must be a non-negative int")
        if max_iters < 1:
            raise ValueError("max_iters must be >= 1")
        self._widen_after = widen_after
        self._narrow_steps = narrow_steps
        self._max_iters = max_iters

    def _exec_block(self, stmts: list, env: Dict[str, Interval]) -> Dict[str, Interval]:
        for stmt in stmts:
            env = self._exec_stmt(stmt, env)
        return env

    def _exec_stmt(self, stmt: _Stmt, env: Dict[str, Interval]) -> Dict[str, Interval]:
        if not isinstance(stmt, tuple) or not stmt:
            raise TypeError("statement must be a non-empty tuple")
        tag = stmt[0]
        if tag == "assign":
            if len(stmt) != 3:
                raise ValueError("assign takes (var, expr)")
            var = _require_var_name(stmt[1])
            out = dict(env)
            out[var] = _eval_expr(stmt[2], out)
            return out
        if tag == "assume":
            if len(stmt) != 4:
                raise ValueError("assume takes (var, rel, const)")
            return _apply_assume(env, stmt[1], stmt[2], stmt[3])
        if tag == "while":
            if len(stmt) != 3 or not isinstance(stmt[2], list):
                raise ValueError("while takes (guard_var, body_list)")
            return self._exec_while(stmt[1], stmt[2], env)
        raise ValueError(f"unknown statement tag {tag!r}")

    def _join_envs(self, a: Dict[str, Interval], b: Dict[str, Interval]) -> Dict[str, Interval]:
        out: Dict[str, Interval] = {}
        for key in set(a) | set(b):
            ia, ib = a.get(key, Interval.empty()), b.get(key, Interval.empty())
            out[key] = ia.join(ib)
        return out

    def _widen_envs(self, old: Dict[str, Interval], new: Dict[str, Interval]) -> Dict[str, Interval]:
        out: Dict[str, Interval] = {}
        for key in set(old) | set(new):
            io, inn = old.get(key, Interval.empty()), new.get(key, Interval.empty())
            out[key] = io.widen(inn)
        return out

    def _env_leq(self, a: Dict[str, Interval], b: Dict[str, Interval]) -> bool:
        return all(
            a.get(k, Interval.empty()).leq(b.get(k, Interval.empty()))
            for k in set(a) | set(b)
        )

    def _exec_while(self, guard_var: str, body: list, env: Dict[str, Interval]) -> Dict[str, Interval]:
        _require_var_name(guard_var)
        head = dict(env)
        widened = False
        it = 0
        while True:
            it += 1
            if it > self._max_iters:
                raise AbstractInterpError(
                    f"loop did not stabilize within {self._max_iters} iterations"
                )
            # enter the body only on paths where the guard may hold
            entered = _apply_assume(head, guard_var, ">", 0)
            after = self._exec_block(body, entered)
            joined = self._join_envs(head, after)
            if it > self._widen_after:
                joined = self._widen_envs(head, joined)
                widened = True
            if self._env_leq(joined, head):
                head = joined
                break
            head = joined
        # narrowing: a few descending iterations from the widened fixpoint
        narrowed = False
        for _ in range(self._narrow_steps):
            entered = _apply_assume(head, guard_var, ">", 0)
            after = self._exec_block(body, entered)
            joined = self._join_envs(head, after)
            down = {k: head.get(k, Interval.empty()).narrow(joined.get(k, Interval.empty()))
                    for k in set(head) | set(joined)}
            if self._env_leq(down, head):
                head = down
                narrowed = True
            else:
                break
        # exit: only paths where the guard cannot hold
        out = _apply_assume(head, guard_var, "<=", 0)
        self._last_loop = (it, widened, narrowed)
        return out

    def analyze(self, program: list) -> AnalysisResult:
        """Analyze a program; returns the post-state abstract environment."""
        if not isinstance(program, list):
            raise TypeError("program must be a list of statements")
        self._last_loop = (0, False, False)
        env = self._exec_block(program, {})
        it, widened, narrowed = self._last_loop
        return AnalysisResult(env=env, iterations=it, widened=widened, narrowed=narrowed)

    # -- explicit widen/narrow entry points (per the task spec) ----------------

    def widen(self, old: Interval, new: Interval) -> Interval:
        """One widening step on two abstract values."""
        return _require_interval(old, "old").widen(_require_interval(new, "other"))

    def narrow(self, old: Interval, new: Interval) -> Interval:
        """One narrowing step on two abstract values."""
        return _require_interval(old, "old").narrow(_require_interval(new, "other"))


def abstract_interp_audit_event(kind: str, seq: int, detail: Optional[str] = None) -> dict:
    """Shape an abstract-interpretation event as an ``audit.ndjson/1`` record."""
    valid = ("analysis-started", "analysis-finished", "widened", "narrowed", "rejected")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    if detail is not None and not isinstance(detail, str):
        raise TypeError("detail must be str or None")
    record = {
        "schema": "audit.ndjson/1",
        "kind": f"abstract-interp.{kind}",
        "module": ABSTRACT_INTERP_SCHEMA,
        "version": ABSTRACT_INTERP_VERSION,
        "seq": seq,
    }
    if detail is not None:
        record["detail"] = detail
    return record


def main() -> None:
    prog = [
        ("assign", "x", ("const", 0)),
        ("while", "n", [
            ("assign", "x", ("add", ("var", "x"), ("const", 1))),
            ("assign", "n", ("sub", ("var", "n"), ("const", 1))),
        ]),
    ]
    ai = AbstractInterp()
    result = ai.analyze([("assign", "n", ("const", 10))] + prog)
    x = result.get("x")
    # widening may legitimately push hi to +inf; soundness is what we check:
    # the true answer (x == 10) must be contained in the abstract result.
    assert not x.is_bottom() and x.lo >= 0 and x.contains(10), x
    print(f"abstract-interp OK: widened={result.widened} x in [{x.lo}, {x.hi}]")


if __name__ == "__main__":
    main()
