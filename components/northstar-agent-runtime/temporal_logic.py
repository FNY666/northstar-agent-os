"""Linear temporal logic (LTL) over finite traces: check one reported run.

A :class:`TemporalLogic` wraps an LTL formula and evaluates it against a
*finite trace* -- a sequence of states, each state the set of atomic
propositions reported true at that step. Finite-trace semantics follows
the LTLf tradition (De Giacomo & Vardi): every quantifier ranges over
the positions ``0 .. n-1`` of the given trace, and the strong next
operator ``X`` is false at the last position.

This is boolean model checking of a *single trace*, not full model
checking of a state machine (that is a different module's job). It
answers "did this reported run satisfy the property?", which is exactly
what an audit pipeline needs: a temporal property like
``G (request -> F grant)`` can be checked against the recorded event
sequence, and a violation is evidence in the audit trail.

Formulas are immutable values built from combinators::

    tl = TemporalLogic.parse("G (request -> F grant)")
    ok = tl.check([{"request"}, set(), {"grant"}])   # True

House rules: frozen dataclasses, no wall-clock (traces are caller
sequences, never "now"), fail-closed validation (empty traces, empty
proposition names, malformed formula text are refused, never guessed),
stdlib-only, deterministic (identical inputs give identical verdicts,
so audit replay is exact).

Honest scope: the checker proves properties of the *reported* trace --
unreported steps do not exist as far as it is concerned, and a host
that omits a violating step gets a clean verdict. A ``True`` verdict
means "this trace satisfies the formula", never "the system is
correct". ``X`` is the strong next (false at the trace end); use ``W``
(weak next) when the end-of-trace position should count as satisfied.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import FrozenSet, List, Sequence, Tuple, Union


#: Version pin for this module's record shape.
TEMPORAL_LOGIC_VERSION = "temporal-logic.v1"

#: Schema pin carried on audit records.
TEMPORAL_LOGIC_SCHEMA = "northstar.temporal-logic.v1"

#: Domain prefix for formula digest pins.
_PIN_DOMAIN = b"northstar.temporal-logic.v1/formula"

#: Atomic proposition names must be non-empty strings; bool is rejected
#: explicitly (``True == 1`` must never alias a proposition).


class TemporalLogicError(Exception):
    """Base error for temporal-logic failures."""


class ParseError(TemporalLogicError):
    """Raised when formula text cannot be parsed."""


# ---------------------------------------------------------------------------
# Formulas (frozen, structural equality)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Formula:
    """Base class for LTL formulas. Use the combinators, not subclasses."""

    def __and__(self, other: "FormulaLike") -> "And":
        return And(self, _coerce(other))

    def __or__(self, other: "FormulaLike") -> "Or":
        return Or(self, _coerce(other))

    def __invert__(self) -> "Not":
        return Not(self)

    def implies(self, other: "FormulaLike") -> "Implies":
        """Logical implication: ``self -> other``."""
        return Implies(self, _coerce(other))

    def as_dict(self) -> dict:
        """JSON-shaped structural view with the schema pin."""
        return {
            "schema": TEMPORAL_LOGIC_SCHEMA,
            "version": TEMPORAL_LOGIC_VERSION,
            "formula": str(self),
            "pin": formula_pin(self),
        }

    def __str__(self) -> str:
        return _format(self)


@dataclass(frozen=True)
class TTrue(Formula):
    pass


@dataclass(frozen=True)
class TFalse(Formula):
    pass


@dataclass(frozen=True)
class Atom(Formula):
    name: str

    def __post_init__(self) -> None:
        if isinstance(self.name, bool) or not isinstance(self.name, str):
            raise TemporalLogicError("proposition name must be a str")
        if not self.name:
            raise TemporalLogicError("proposition name must be non-empty")


@dataclass(frozen=True)
class Not(Formula):
    operand: Formula

    def __post_init__(self) -> None:
        _require_formula(self.operand, "Not operand")


@dataclass(frozen=True)
class And(Formula):
    left: Formula
    right: Formula

    def __post_init__(self) -> None:
        _require_formula(self.left, "And left")
        _require_formula(self.right, "And right")


@dataclass(frozen=True)
class Or(Formula):
    left: Formula
    right: Formula

    def __post_init__(self) -> None:
        _require_formula(self.left, "Or left")
        _require_formula(self.right, "Or right")


@dataclass(frozen=True)
class Implies(Formula):
    left: Formula
    right: Formula

    def __post_init__(self) -> None:
        _require_formula(self.left, "Implies left")
        _require_formula(self.right, "Implies right")


@dataclass(frozen=True)
class Next(Formula):
    """Strong next: false at the last trace position."""

    operand: Formula

    def __post_init__(self) -> None:
        _require_formula(self.operand, "Next operand")


@dataclass(frozen=True)
class WeakNext(Formula):
    """Weak next: true at the last trace position."""

    operand: Formula

    def __post_init__(self) -> None:
        _require_formula(self.operand, "WeakNext operand")


@dataclass(frozen=True)
class Always(Formula):
    operand: Formula

    def __post_init__(self) -> None:
        _require_formula(self.operand, "Always operand")


@dataclass(frozen=True)
class Eventually(Formula):
    operand: Formula

    def __post_init__(self) -> None:
        _require_formula(self.operand, "Eventually operand")


@dataclass(frozen=True)
class Until(Formula):
    left: Formula
    right: Formula

    def __post_init__(self) -> None:
        _require_formula(self.left, "Until left")
        _require_formula(self.right, "Until right")


@dataclass(frozen=True)
class Release(Formula):
    left: Formula
    right: Formula

    def __post_init__(self) -> None:
        _require_formula(self.left, "Release left")
        _require_formula(self.right, "Release right")


#: Anything a combinator accepts: a formula, or a bare proposition name.
FormulaLike = Union[Formula, str]


def _require_formula(value: object, what: str) -> None:
    if not isinstance(value, Formula):
        raise TemporalLogicError(f"{what} must be a Formula")


def _coerce(value: FormulaLike) -> Formula:
    """Accept a Formula or a bare proposition name (never silently None)."""
    if isinstance(value, Formula):
        return value
    if isinstance(value, bool) or not isinstance(value, str):
        raise TemporalLogicError("expected a Formula or proposition name")
    return Atom(value)


# ---------------------------------------------------------------------------
# Canonical printing (precedence-aware, parse round-trips)
# ---------------------------------------------------------------------------

_PRECEDENCE = {
    TTrue: 6,
    TFalse: 6,
    Atom: 6,
    Not: 5,
    Next: 5,
    WeakNext: 5,
    Always: 5,
    Eventually: 5,
    Until: 4,
    Release: 4,
    And: 3,
    Or: 2,
    Implies: 1,
}

_UNARY_SYMBOL = {Not: "!", Next: "X", WeakNext: "W", Always: "G", Eventually: "F"}
_BINARY_SYMBOL = {And: "&&", Or: "||", Implies: "->", Until: "U", Release: "R"}


def _prec(formula: Formula) -> int:
    return _PRECEDENCE[type(formula)]


def _format(formula: Formula) -> str:
    if isinstance(formula, TTrue):
        return "true"
    if isinstance(formula, TFalse):
        return "false"
    if isinstance(formula, Atom):
        return formula.name
    if type(formula) in _UNARY_SYMBOL:
        sym = _UNARY_SYMBOL[type(formula)]
        inner = _format(formula.operand)
        if _prec(formula.operand) < 5:
            inner = f"({inner})"
        return f"{sym} {inner}" if sym != "!" else f"!{inner}"
    if type(formula) in _BINARY_SYMBOL:
        sym = _BINARY_SYMBOL[type(formula)]
        prec = _prec(formula)
        left = _format(formula.left)
        right = _format(formula.right)
        if _prec(formula.left) < prec:
            left = f"({left})"
        # "->" is right-associative; the rest are left-associative.
        need = prec if isinstance(formula, Implies) else prec + 1
        if _prec(formula.right) < need:
            right = f"({right})"
        return f"{left} {sym} {right}"
    raise TemporalLogicError(f"unknown formula node {type(formula).__name__}")


def formula_pin(formula: Formula) -> str:
    """``sha256:`` pin binding a formula's canonical text (domain-separated)."""
    _require_formula(formula, "formula_pin")
    digest = hashlib.sha256(_PIN_DOMAIN + b"\x00" + _format(formula).encode("utf-8"))
    return "sha256:" + digest.hexdigest()


# ---------------------------------------------------------------------------
# Parser (recursive descent, fail-closed)
# ---------------------------------------------------------------------------

_TOKEN_CHARS = set("!&|->()")


def _tokenize(text: str) -> List[str]:
    if isinstance(text, bool) or not isinstance(text, str):
        raise ParseError("formula text must be a str")
    if not text.strip():
        raise ParseError("formula text must be non-empty")
    tokens: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c == "(" or c == ")":
            tokens.append(c)
            i += 1
            continue
        if c == "!":
            tokens.append("!")
            i += 1
            continue
        if text.startswith("&&", i):
            tokens.append("&&")
            i += 2
            continue
        if text.startswith("||", i):
            tokens.append("||")
            i += 2
            continue
        if text.startswith("->", i):
            tokens.append("->")
            i += 2
            continue
        if c.isalpha() or c == "_":
            j = i
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            tokens.append(text[i:j])
            i = j
            continue
        raise ParseError(f"unexpected character {c!r} at position {i}")
    return tokens


class _Parser:
    def __init__(self, tokens: List[str]) -> None:
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> str:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else ""

    def _take(self, expected: str) -> None:
        if self._peek() != expected:
            raise ParseError(f"expected {expected!r}, found {self._peek()!r}")
        self._pos += 1

    def parse(self) -> Formula:
        formula = self._impl()
        if self._pos != len(self._tokens):
            raise ParseError(f"trailing tokens: {self._tokens[self._pos:]!r}")
        return formula

    def _impl(self) -> Formula:
        left = self._or()
        if self._peek() == "->":
            self._take("->")
            return Implies(left, self._impl())  # right-associative
        return left

    def _or(self) -> Formula:
        left = self._and()
        while self._peek() == "||":
            self._take("||")
            left = Or(left, self._and())
        return left

    def _and(self) -> Formula:
        left = self._temporal()
        while self._peek() == "&&":
            self._take("&&")
            left = And(left, self._temporal())
        return left

    def _temporal(self) -> Formula:
        # U / R share one precedence level and are left-associative, so
        # "a U b U c" parses as "(a U b) U c".
        left = self._unary()
        while self._peek() in ("U", "R"):
            tok = self._peek()
            self._take(tok)
            right = self._unary()
            left = Until(left, right) if tok == "U" else Release(left, right)
        return left

    def _unary(self) -> Formula:
        tok = self._peek()
        if tok == "!":
            self._take("!")
            return Not(self._unary())
        if tok in ("G", "F", "X", "W"):
            self._take(tok)
            node = {"G": Always, "F": Eventually, "X": Next, "W": WeakNext}[tok]
            return node(self._unary())
        return self._primary()

    def _primary(self) -> Formula:
        tok = self._peek()
        if tok == "(":
            self._take("(")
            if self._peek() == ")":
                raise ParseError("empty parentheses")
            formula = self._impl()
            self._take(")")
            return formula
        if tok == "true":
            self._take("true")
            return TTrue()
        if tok == "false":
            self._take("false")
            return TFalse()
        if tok and (tok[0].isalpha() or tok[0] == "_"):
            self._pos += 1
            return Atom(tok)
        raise ParseError(f"unexpected token {tok!r}")


def parse_formula(text: str) -> Formula:
    """Parse LTL formula text into a frozen :class:`Formula`.

    Grammar (precedence, tightest first): ``! G F X W`` > ``U R`` >
    ``&&`` > ``||`` > ``->`` (right-associative). Identifiers are
    ``[A-Za-z_][A-Za-z0-9_]*``; ``true``/``false`` are constants. The
    operator names ``G F X W U R`` are reserved and cannot be used as
    proposition names (a host that needs such a name must rename it).
    """
    return _Parser(_tokenize(text)).parse()


# ---------------------------------------------------------------------------
# Finite-trace evaluation (LTLf semantics)
# ---------------------------------------------------------------------------


def _eval(formula: Formula, states: Tuple[FrozenSet[str], ...], pos: int) -> bool:
    n = len(states)
    if isinstance(formula, TTrue):
        return True
    if isinstance(formula, TFalse):
        return False
    if isinstance(formula, Atom):
        return formula.name in states[pos]
    if isinstance(formula, Not):
        return not _eval(formula.operand, states, pos)
    if isinstance(formula, And):
        return _eval(formula.left, states, pos) and _eval(formula.right, states, pos)
    if isinstance(formula, Or):
        return _eval(formula.left, states, pos) or _eval(formula.right, states, pos)
    if isinstance(formula, Implies):
        return not _eval(formula.left, states, pos) or _eval(formula.right, states, pos)
    if isinstance(formula, Next):
        return pos + 1 < n and _eval(formula.operand, states, pos + 1)
    if isinstance(formula, WeakNext):
        return pos + 1 >= n or _eval(formula.operand, states, pos + 1)
    if isinstance(formula, Always):
        return all(_eval(formula.operand, states, j) for j in range(pos, n))
    if isinstance(formula, Eventually):
        return any(_eval(formula.operand, states, j) for j in range(pos, n))
    if isinstance(formula, Until):
        for j in range(pos, n):
            if _eval(formula.right, states, j):
                if all(_eval(formula.left, states, k) for k in range(pos, j)):
                    return True
        return False
    if isinstance(formula, Release):
        # f R g  <=>  not (not-f U not-g)
        return not _eval(Until(Not(formula.left), Not(formula.right)), states, pos)
    raise TemporalLogicError(f"unknown formula node {type(formula).__name__}")


def _coerce_state(state: object, index: int) -> FrozenSet[str]:
    if isinstance(state, (set, frozenset, list, tuple)):
        items = list(state)
    else:
        raise TemporalLogicError(f"trace state {index} must be a set/frozenset/list/tuple")
    for item in items:
        if isinstance(item, bool) or not isinstance(item, str):
            raise TemporalLogicError(f"trace state {index}: propositions must be str")
        if not item:
            raise TemporalLogicError(f"trace state {index}: proposition names must be non-empty")
    return frozenset(items)


def coerce_trace(trace: Sequence[object]) -> Tuple[FrozenSet[str], ...]:
    """Validate a trace; empty traces are refused (fail-closed)."""
    if not isinstance(trace, (list, tuple)):
        raise TemporalLogicError("trace must be a list or tuple of states")
    if len(trace) == 0:
        raise TemporalLogicError("trace must be non-empty")
    return tuple(_coerce_state(s, i) for i, s in enumerate(trace))


@dataclass(frozen=True)
class TraceVerdict:
    """Frozen verdict of checking one formula against one trace."""

    formula: str
    formula_pin: str
    holds: bool
    trace_length: int
    schema: str = TEMPORAL_LOGIC_SCHEMA

    def as_dict(self) -> dict:
        return {
            "schema": self.schema,
            "version": TEMPORAL_LOGIC_VERSION,
            "formula": self.formula,
            "formula_pin": self.formula_pin,
            "holds": self.holds,
            "trace_length": self.trace_length,
        }


# ---------------------------------------------------------------------------
# TemporalLogic: the public interface
# ---------------------------------------------------------------------------


class TemporalLogic:
    """An LTL formula plus the operations to build and check it."""

    def __init__(self, formula: Formula) -> None:
        _require_formula(formula, "TemporalLogic")
        self._formula = formula

    @property
    def formula(self) -> Formula:
        return self._formula

    # -- combinators (accept Formula or bare proposition name) ---------------

    @staticmethod
    def atom(name: str) -> Atom:
        return Atom(name)

    @staticmethod
    def always(phi: FormulaLike) -> Always:
        """``G phi``: phi holds at every position."""
        return Always(_coerce(phi))

    @staticmethod
    def eventually(phi: FormulaLike) -> Eventually:
        """``F phi``: phi holds at some position."""
        return Eventually(_coerce(phi))

    @staticmethod
    def until(phi: FormulaLike, psi: FormulaLike) -> Until:
        """``phi U psi``: phi holds until psi holds (psi must hold)."""
        return Until(_coerce(phi), _coerce(psi))

    @staticmethod
    def next(phi: FormulaLike) -> Next:
        """``X phi``: strong next -- false at the trace end."""
        return Next(_coerce(phi))

    @staticmethod
    def weak_next(phi: FormulaLike) -> WeakNext:
        """``W phi``: weak next -- true at the trace end."""
        return WeakNext(_coerce(phi))

    @staticmethod
    def release(phi: FormulaLike, psi: FormulaLike) -> Release:
        """``phi R psi``: psi holds up to and including the first phi."""
        return Release(_coerce(phi), _coerce(psi))

    # -- parsing / checking ----------------------------------------------------

    @classmethod
    def parse(cls, text: str) -> "TemporalLogic":
        """Parse formula text (see :func:`parse_formula` for the grammar)."""
        return cls(parse_formula(text))

    def check(self, trace: Sequence[object]) -> bool:
        """True iff the formula holds at position 0 of the trace."""
        return _eval(self._formula, coerce_trace(trace), 0)

    def verdict(self, trace: Sequence[object]) -> TraceVerdict:
        """Frozen :class:`TraceVerdict` for one formula against one trace."""
        states = coerce_trace(trace)
        return TraceVerdict(
            formula=_format(self._formula),
            formula_pin=formula_pin(self._formula),
            holds=_eval(self._formula, states, 0),
            trace_length=len(states),
        )

    def __str__(self) -> str:
        return _format(self._formula)

    def __repr__(self) -> str:
        return f"TemporalLogic({_format(self._formula)!r})"


def temporal_logic_audit_event(kind: str, logic: TemporalLogic, seq: int) -> dict:
    """Shape a temporal-logic lifecycle event as an ``audit.ndjson/1`` record."""
    valid = ("parsed", "checked")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    if not isinstance(logic, TemporalLogic):
        raise TypeError("logic must be a TemporalLogic")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"temporal-logic.{kind}",
        "module": TEMPORAL_LOGIC_SCHEMA,
        "version": TEMPORAL_LOGIC_VERSION,
        "seq": seq,
        "formula": str(logic),
        "formula_pin": formula_pin(logic.formula),
    }


def main() -> None:
    tl = TemporalLogic.parse("G (request -> F grant)")
    assert tl.check([{"request"}, set(), {"grant"}]) is True
    assert tl.check([{"request"}, set(), set()]) is False
    mutual = TemporalLogic.parse("G !(crit_a && crit_b)")
    assert mutual.check([{"crit_a"}, {"crit_b"}, set()]) is True
    assert mutual.check([{"crit_a", "crit_b"}]) is False
    live = TemporalLogic(TemporalLogic.always(TemporalLogic.until("work", "done")))
    assert live.check([{"work"}, {"work", "done"}]) is True
    assert live.check([{"work"}, {"work"}]) is False
    nxt = TemporalLogic(TemporalLogic.next("p"))
    assert nxt.check([set(), {"p"}]) is True
    assert nxt.check([{"p"}]) is False  # strong next fails at trace end
    weak = TemporalLogic(TemporalLogic.weak_next("p"))
    assert weak.check([{"p"}]) is True
    verdict = tl.verdict([{"request"}])
    assert verdict.holds is False and verdict.trace_length == 1
    print("temporal-logic OK: parse, G/F/U, strong/weak next, verdicts")


if __name__ == "__main__":
    main()
