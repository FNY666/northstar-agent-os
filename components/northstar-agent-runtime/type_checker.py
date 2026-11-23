"""Simply-typed lambda calculus (STLC) type checker: check / infer.

A tiny, total, decidable type system for validating the *shape* of terms
before they are trusted -- e.g. policy DSL fragments, structured tool
arguments, or generated plans that must conform to a declared interface.
The checker answers one question: "does this term have this type?" It
never runs the term and never inspects raw payloads beyond their type
structure.

The language (Church-style, explicitly annotated binders)::

    types  A,B ::= Nat | Bool | A -> B
    terms  t   ::= x | lam x:A. t | t t | n | b
                | if t then t else t | let x = t in t

Typing rules (bidirectional)::

    infer(x)                = Gamma(x)            (unbound x is an error)
    infer(n)                = Nat
    infer(b)                = Bool
    infer(lam x:A. t)       = A -> infer(t)       (under Gamma, x:A)
    infer(t1 t2)            = B  where infer(t1) = A -> B and t2 checks at A
    infer(if c then a else b) = T where c checks at Bool,
                                infer(a) = T, b checks at T
    infer(let x = v in t)   = infer(t)            (under Gamma, x:infer(v))

    check(lam x:A'. t, A -> B) holds iff A' = A and t checks at B
                                (under Gamma, x:A)
    check(t, A)             holds iff infer(t) = A      (otherwise)

``infer`` returns the type or raises ``TypeCheckError`` (there is no type
to return for an ill-typed term). ``check`` returns a boolean verdict --
``True`` when the term has the expected type, ``False`` on a genuine
mismatch -- and raises ``TypeCheckError`` only for malformed input
(a non-term, a non-type, an unbound variable reached through ``infer``).

Honest scope: this is the *simply*-typed lambda calculus, not dependent
types -- types cannot mention terms, so properties like "a list of length
n" are inexpressible here; the module pins exactly the STLC fragment
above. There is no recursion operator and no general fixpoint, so every
well-typed term is strongly normalizing (it terminates); the checker does
not prove termination, the language simply cannot express divergence.
Binders are explicitly annotated (Church style), which is what makes
inference decidable and complete -- unannotated terms are rejected at
construction, never guessed. ``Nat`` has literals but no eliminator
(no primitive recursion); ``Bool`` is eliminated only by ``if``. An
unbound variable is a hard error, never defaulted. Type equality is purely
structural. This module type-checks *reported* terms; it cannot prove
anything about code the host never submits.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, FrozenSet, Mapping, Optional, Union


#: Version pin for this module's record shape.
TYPE_CHECKER_VERSION = "type-checker.v1"

#: Schema pin carried on audit records.
TYPE_CHECKER_SCHEMA = "northstar.type-checker.v1"

#: Domain-separation prefix so digest pins cannot collide with pins from
#: other modules.
_DOMAIN = b"northstar.type-checker.v1:"


class TypeCheckError(Exception):
    """Raised for malformed terms/types, and by ``infer`` on ill-typed terms."""


class _TypeMismatch(TypeCheckError):
    """Internal control flow: a well-formed term at the wrong type.

    Caught by ``TypeChecker.check`` and turned into ``False``; never
    escapes to callers.
    """

    def __init__(self, found: "Type", expected: "Type", detail: str = "") -> None:
        self.found = found
        self.expected = expected
        self.detail = detail
        super().__init__(
            f"type mismatch: found {type_to_str(found)}, "
            f"expected {type_to_str(expected)}"
            + (f" ({detail})" if detail else "")
        )


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NatType:
    """The base type of natural numbers."""


@dataclass(frozen=True)
class BoolType:
    """The base type of booleans."""


@dataclass(frozen=True)
class ArrowType:
    """A function type ``domain -> codomain``."""

    domain: "Type"
    codomain: "Type"

    def __post_init__(self) -> None:
        _require_type(self.domain, "domain")
        _require_type(self.codomain, "codomain")


#: Every well-formed type.
Type = Union[NatType, BoolType, ArrowType]

_TYPE_TYPES = (NatType, BoolType, ArrowType)


def _require_type(value: object, name: str) -> "Type":
    if not isinstance(value, _TYPE_TYPES):
        raise TypeCheckError(
            f"{name} must be a Type (NatType/BoolType/ArrowType), "
            f"got {type(value).__name__}"
        )
    return value  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Terms
# ---------------------------------------------------------------------------


def _require_name(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) == 0:
        raise TypeCheckError(f"{name} must be a non-empty str")
    return value


@dataclass(frozen=True)
class Var:
    """A variable reference."""

    name: str

    def __post_init__(self) -> None:
        _require_name(self.name, "variable name")


@dataclass(frozen=True)
class Lam:
    """Lambda abstraction ``lam param:param_type. body`` (annotated binder)."""

    param: str
    param_type: "Type"
    body: "Term"

    def __post_init__(self) -> None:
        _require_name(self.param, "parameter name")
        _require_type(self.param_type, "parameter type")
        _require_term(self.body, "lambda body")


@dataclass(frozen=True)
class App:
    """Function application ``func arg``."""

    func: "Term"
    arg: "Term"

    def __post_init__(self) -> None:
        _require_term(self.func, "application function")
        _require_term(self.arg, "application argument")


@dataclass(frozen=True)
class LitNat:
    """A natural-number literal."""

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise TypeCheckError("Nat literal value must be an int")
        if self.value < 0:
            raise TypeCheckError("Nat literal value must be non-negative")


@dataclass(frozen=True)
class LitBool:
    """A boolean literal."""

    value: bool

    def __post_init__(self) -> None:
        if not isinstance(self.value, bool):
            raise TypeCheckError("Bool literal value must be a bool")


@dataclass(frozen=True)
class If:
    """Conditional ``if cond then then_branch else else_branch``."""

    cond: "Term"
    then_branch: "Term"
    else_branch: "Term"

    def __post_init__(self) -> None:
        _require_term(self.cond, "if condition")
        _require_term(self.then_branch, "if then-branch")
        _require_term(self.else_branch, "if else-branch")


@dataclass(frozen=True)
class Let:
    """Let-binding ``let name = value in body``."""

    name: str
    value: "Term"
    body: "Term"

    def __post_init__(self) -> None:
        _require_name(self.name, "let-bound name")
        _require_term(self.value, "let value")
        _require_term(self.body, "let body")


#: Every well-formed term.
Term = Union[Var, Lam, App, LitNat, LitBool, If, Let]

_TERM_TYPES = (Var, Lam, App, LitNat, LitBool, If, Let)


def _require_term(value: object, name: str) -> "Term":
    if not isinstance(value, _TERM_TYPES):
        raise TypeCheckError(
            f"{name} must be a Term "
            f"(Var/Lam/App/LitNat/LitBool/If/Let), got {type(value).__name__}"
        )
    return value  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------


def type_to_str(typ: "Type") -> str:
    """Render a type in conventional notation (``->`` right-associative)."""
    _require_type(typ, "type")
    if isinstance(typ, NatType):
        return "Nat"
    if isinstance(typ, BoolType):
        return "Bool"
    domain = type_to_str(typ.domain)
    if isinstance(typ.domain, ArrowType):
        domain = f"({domain})"
    return f"{domain} -> {type_to_str(typ.codomain)}"


def term_to_str(term: "Term") -> str:
    """Render a term for human-readable diagnostics (not canonical)."""
    _require_term(term, "term")
    if isinstance(term, Var):
        return term.name
    if isinstance(term, Lam):
        return (
            f"(lam {term.param}:{type_to_str(term.param_type)}. "
            f"{term_to_str(term.body)})"
        )
    if isinstance(term, App):
        return f"({term_to_str(term.func)} {term_to_str(term.arg)})"
    if isinstance(term, LitNat):
        return str(term.value)
    if isinstance(term, LitBool):
        return "true" if term.value else "false"
    if isinstance(term, If):
        return (
            f"(if {term_to_str(term.cond)} "
            f"then {term_to_str(term.then_branch)} "
            f"else {term_to_str(term.else_branch)})"
        )
    # Let
    return (
        f"(let {term.name} = {term_to_str(term.value)} "
        f"in {term_to_str(term.body)})"
    )


# ---------------------------------------------------------------------------
# Canonical digests and free variables
# ---------------------------------------------------------------------------


def _enc_name(name: str) -> bytes:
    raw = name.encode("utf-8")
    return len(raw).to_bytes(8, "big") + raw


def _canonical_type(typ: "Type") -> bytes:
    if isinstance(typ, NatType):
        return b"T:Nat"
    if isinstance(typ, BoolType):
        return b"T:Bool"
    return b"T:->" + _canonical_type(typ.domain) + _canonical_type(typ.codomain)


def _canonical_term(term: "Term") -> bytes:
    if isinstance(term, Var):
        return b"t:var" + _enc_name(term.name)
    if isinstance(term, Lam):
        return (
            b"t:lam"
            + _enc_name(term.param)
            + _canonical_type(term.param_type)
            + _canonical_term(term.body)
        )
    if isinstance(term, App):
        return b"t:app" + _canonical_term(term.func) + _canonical_term(term.arg)
    if isinstance(term, LitNat):
        raw = term.value.to_bytes((term.value.bit_length() + 7) // 8 or 1, "big")
        return b"t:nat" + len(raw).to_bytes(8, "big") + raw
    if isinstance(term, LitBool):
        return b"t:bool" + (b"\x01" if term.value else b"\x00")
    if isinstance(term, If):
        return (
            b"t:if"
            + _canonical_term(term.cond)
            + _canonical_term(term.then_branch)
            + _canonical_term(term.else_branch)
        )
    # Let
    return (
        b"t:let"
        + _enc_name(term.name)
        + _canonical_term(term.value)
        + _canonical_term(term.body)
    )


def term_digest(term: "Term") -> str:
    """Pin a term's identity: ``sha256:`` over its canonical encoding."""
    _require_term(term, "term")
    return "sha256:" + hashlib.sha256(
        _DOMAIN + b"term:" + _canonical_term(term)
    ).hexdigest()


def free_vars(term: "Term") -> FrozenSet[str]:
    """The set of unbound variable names occurring in ``term``."""
    _require_term(term, "term")
    if isinstance(term, Var):
        return frozenset({term.name})
    if isinstance(term, Lam):
        return free_vars(term.body) - {term.param}
    if isinstance(term, App):
        return free_vars(term.func) | free_vars(term.arg)
    if isinstance(term, (LitNat, LitBool)):
        return frozenset()
    if isinstance(term, If):
        return (
            free_vars(term.cond)
            | free_vars(term.then_branch)
            | free_vars(term.else_branch)
        )
    # Let
    return free_vars(term.value) | (free_vars(term.body) - {term.name})


# ---------------------------------------------------------------------------
# The checker
# ---------------------------------------------------------------------------


class TypeChecker:
    """Bidirectional type checker for STLC.

    The context is immutable: :meth:`extend` returns a new checker, so a
    checker value is a snapshot that can be shared, cached, and replayed
    without interference.
    """

    def __init__(self, context: Optional[Mapping[str, "Type"]] = None) -> None:
        ctx: Dict[str, "Type"] = {}
        if context is not None:
            if not isinstance(context, Mapping):
                raise TypeCheckError("context must be a mapping of name -> Type")
            for key, value in context.items():
                _require_name(key, "context key")
                _require_type(value, "context value")
                ctx[key] = value
        self._context: Dict[str, "Type"] = ctx

    @property
    def context(self) -> Dict[str, "Type"]:
        """A copy of the current typing context."""
        return dict(self._context)

    def extend(self, name: str, typ: "Type") -> "TypeChecker":
        """Return a new checker with ``name: typ`` added (shadowing allowed)."""
        _require_name(name, "binding name")
        _require_type(typ, "binding type")
        merged = dict(self._context)
        merged[name] = typ
        return TypeChecker(merged)

    # -- inference ------------------------------------------------------

    def infer(self, term: "Term") -> "Type":
        """Infer ``term``'s type; raises ``TypeCheckError`` if ill-typed."""
        _require_term(term, "term")
        if isinstance(term, Var):
            try:
                return self._context[term.name]
            except KeyError:
                raise TypeCheckError(
                    f"unbound variable: {term.name!r}"
                ) from None
        if isinstance(term, LitNat):
            return NatType()
        if isinstance(term, LitBool):
            return BoolType()
        if isinstance(term, Lam):
            body_type = self.extend(term.param, term.param_type).infer(term.body)
            return ArrowType(term.param_type, body_type)
        if isinstance(term, App):
            func_type = self.infer(term.func)
            if not isinstance(func_type, ArrowType):
                raise TypeCheckError(
                    f"application of non-function of type "
                    f"{type_to_str(func_type)} in {term_to_str(term)}"
                )
            self._check(term.arg, func_type.domain)
            return func_type.codomain
        if isinstance(term, If):
            self._check(term.cond, BoolType())
            branch_type = self.infer(term.then_branch)
            self._check(term.else_branch, branch_type)
            return branch_type
        # Let
        value_type = self.infer(term.value)
        return self.extend(term.name, value_type).infer(term.body)

    # -- checking --------------------------------------------------------

    def _check(self, term: "Term", expected: "Type") -> None:
        """Bidirectional check; raises ``_TypeMismatch`` on genuine mismatch."""
        if isinstance(term, Lam) and isinstance(expected, ArrowType):
            if term.param_type != expected.domain:
                raise _TypeMismatch(
                    term.param_type,
                    expected.domain,
                    "lambda annotation does not match expected domain",
                )
            self.extend(term.param, term.param_type)._check(
                term.body, expected.codomain
            )
            return
        found = self.infer(term)
        if found != expected:
            raise _TypeMismatch(found, expected)

    def check(self, term: "Term", expected: "Type") -> bool:
        """Check ``term`` against ``expected``.

        Returns ``True`` when the term has the expected type, ``False`` on a
        genuine type mismatch. Raises ``TypeCheckError`` only for malformed
        input (a non-term, a non-type); an unbound variable surfaces through
        ``infer`` as ``TypeCheckError``.
        """
        _require_term(term, "term")
        _require_type(expected, "expected type")
        try:
            self._check(term, expected)
        except _TypeMismatch:
            return False
        return True


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("inferred", "checked", "check-failed", "infer-failed")


def type_checker_audit_event(
    kind: str, term: "Term", seq: int, *, result: str = ""
) -> dict:
    """Shape an ``audit.ndjson/1`` record for a type-checker operation.

    ``result`` carries the inferred type (for ``inferred``), ``"ok"`` (for
    ``checked``), or a short failure note (for ``check-failed`` /
    ``infer-failed``). The term itself is pinned by digest, never logged raw.
    """
    if kind not in _AUDIT_KINDS:
        raise TypeCheckError(f"unknown audit kind: {kind!r}")
    _require_term(term, "term")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise TypeCheckError("seq must be a non-negative int")
    if not isinstance(result, str):
        raise TypeCheckError("result must be a str")
    return {
        "schema": TYPE_CHECKER_SCHEMA,
        "kind": kind,
        "seq": seq,
        "term_digest": term_digest(term),
        "result": result,
        "version": TYPE_CHECKER_VERSION,
    }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def _self_check() -> None:
    tc = TypeChecker()
    nat, bool_t = NatType(), BoolType()

    # Identity: lam x:Nat. x : Nat -> Nat
    ident = Lam("x", nat, Var("x"))
    assert tc.infer(ident) == ArrowType(nat, nat)
    assert tc.check(ident, ArrowType(nat, nat)) is True
    assert tc.check(ident, ArrowType(bool_t, bool_t)) is False

    # Const: lam x:Nat. lam y:Bool. x : Nat -> Bool -> Nat
    const = Lam("x", nat, Lam("y", bool_t, Var("x")))
    assert tc.infer(const) == ArrowType(nat, ArrowType(bool_t, nat))

    # Application: (lam x:Nat. x) 5 : Nat
    assert tc.infer(App(ident, LitNat(5))) == nat

    # If: if true then 1 else 2 : Nat
    assert tc.infer(If(LitBool(True), LitNat(1), LitNat(2))) == nat

    # Let: let x = 5 in x : Nat
    assert tc.infer(Let("x", LitNat(5), Var("x"))) == nat

    # Failures stay failures.
    for bad in (
        lambda: tc.infer(Var("unbound")),
        lambda: tc.infer(App(LitNat(1), LitNat(2))),
        lambda: tc.infer(App(ident, LitBool(True))),
        lambda: tc.infer(If(LitNat(0), LitNat(1), LitNat(2))),
        lambda: tc.infer(If(LitBool(True), LitNat(1), LitBool(False))),
    ):
        try:
            bad()
        except TypeCheckError:
            pass
        else:
            raise AssertionError("ill-typed term was accepted")

    assert free_vars(Lam("x", nat, App(Var("x"), Var("y")))) == frozenset({"y"})
    assert term_digest(ident) == term_digest(Lam("x", nat, Var("x")))
    assert term_digest(ident) != term_digest(Lam("x", bool_t, Var("x")))
    ev = type_checker_audit_event("inferred", ident, 0, result="Nat -> Nat")
    assert ev["schema"] == TYPE_CHECKER_SCHEMA
    assert ev["kind"] == "inferred"


def main() -> None:
    """Run the built-in self-check."""
    _self_check()
    print("type-checker OK: infer, check, if/let/app, failures rejected")


if __name__ == "__main__":
    main()
