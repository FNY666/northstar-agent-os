"""Floyd-Hoare logic verifier: triples, proof rules, and VCG.

Research basis (second-hand):
- Floyd (1967) / Hoare (1969): partial-correctness triples ``{P} C {Q}`` -
  if ``P`` holds before ``C`` runs and ``C`` terminates, ``Q`` holds after.
- Dijkstra: weakest preconditions; Flanagan-Saxe: verification condition
  generation (VCG) - reduce a triple to a set of purely logical
  implications, then discharge them with a decision procedure.

Design (simulated verification, deterministic):
1. A tiny imperative language: ``skip``, ``x := e`` (affine ``e``),
   sequencing, ``if`` and ``while``. Conditions are *single* linear atoms
   (``x < 10``), so negation stays inside the fragment - no disjunctions.
2. Assertions are conjunctions of linear integer atoms
   (``x >= 0`` / ``y != 3`` / ...). This fragment is decidable: ``implies``
   reduces every goal atom against per-variable interval bounds collected
   from the hypotheses (sound for integer linear arithmetic; contradictory
   hypotheses entail everything, ex falso).
3. ``HoareLogic.triple(pre, prog, post)`` runs VCG - ``wp`` for straight-line
   code, three verification conditions per loop (entry / preservation /
   exit) - and discharges each VC with ``implies``. Loops carry an explicit
   invariant annotation; a loop without one is *refused*, never guessed.
4. The compositional half mirrors the textbook proof rules:
   ``assign_axiom`` / ``skip_axiom`` (axioms), ``sequence_rule``,
   ``if_rule``, ``loop_rule``, ``consequence_rule``. Each rule checks its
   side conditions fail-closed (unverified premise, mismatched middle
   assertion, failed implication) and records the proof tree.

Honest scope: interface + bookkeeping, not a real verifier. A ``True``
verdict means "every generated VC discharged inside the linear-integer
fragment" - never "the program is correct in general". The fragment cannot
express disjunctive invariants, non-linear arithmetic, or heap reasoning;
``while`` needs a host-supplied invariant; termination is not checked
(partial correctness only). Real deployments pair this VCG front-end with
an SMT solver; the triple/record shapes are what this module pins.

No wall-clock anywhere. All functions are pure over the arguments given.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(
            _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True).encode("utf-8")
        ).hexdigest()


#: Version pin for this module's record shape.
HOARE_LOGIC_VERSION = "hoare-logic.v1"

#: Schema pin carried by records and audit events.
HOARE_LOGIC_SCHEMA = "northstar.hoare-logic.v1"

_RELATIONS = ("==", "!=", "<", "<=", ">", ">=")
_NEGATE = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}
_FLIP = {"==": "!=", "!=": "==", "<": ">", "<=": ">=", ">": "<", ">=": "<="}


class HoareLogicError(Exception):
    """Base error: fail-closed on every malformed input."""


class RuleApplicationError(HoareLogicError):
    """A proof rule's side conditions were not met."""


def _check_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise HoareLogicError(f"{name} must be an int, got {type(value).__name__}")
    return value


def _check_name(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise HoareLogicError(f"{name} must be a non-empty str")


# ---------------------------------------------------------------------------
# Expressions and assertions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LinExpr:
    """Affine expression ``coeff * var + const`` (``var=None``: constant)."""

    coeff: int
    var: Optional[str]
    const: int

    def __post_init__(self) -> None:
        _check_int(self.coeff, "coeff")
        _check_int(self.const, "const")
        if self.var is not None:
            _check_name(self.var, "var")

    def as_dict(self) -> Dict[str, Any]:
        return {"coeff": self.coeff, "var": self.var, "const": self.const}


@dataclass(frozen=True)
class Atom:
    """One linear atom ``var <rel> bound`` over integers."""

    var: str
    rel: str
    bound: int

    def __post_init__(self) -> None:
        _check_name(self.var, "var")
        if self.rel not in _RELATIONS:
            raise HoareLogicError(f"unknown relation {self.rel!r}")
        _check_int(self.bound, "bound")

    def negate(self) -> "Atom":
        """Negation of a single atom stays inside the fragment."""
        return Atom(self.var, _NEGATE[self.rel], self.bound)

    def as_dict(self) -> Dict[str, Any]:
        return {"var": self.var, "rel": self.rel, "bound": self.bound}


@dataclass(frozen=True)
class Assertion:
    """Conjunction of atoms. The empty conjunction is ``TRUE``."""

    atoms: FrozenSet[Atom] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        for a in self.atoms:
            if not isinstance(a, Atom):
                raise HoareLogicError("Assertion holds only Atom values")

    @classmethod
    def of(cls, atoms: Iterable[Atom]) -> "Assertion":
        return cls(frozenset(atoms))

    def conjoin(self, other: "Assertion | Atom") -> "Assertion":
        if isinstance(other, Atom):
            other = Assertion.of([other])
        if not isinstance(other, Assertion):
            raise HoareLogicError("can only conjoin Assertion or Atom")
        return Assertion(self.atoms | other.atoms)

    def as_dict(self) -> Dict[str, Any]:
        return {"atoms": sorted(
            (a.as_dict() for a in self.atoms),
            key=lambda d: (d["var"], d["rel"], d["bound"]),
        )}


TRUE = Assertion.of([])


def _ceil_div(p: int, q: int) -> int:
    """Ceiling of p/q for q > 0."""
    return -((-p) // q)


def substitute(assertion: Assertion, var: str, expr: LinExpr) -> Assertion:
    """Substitute ``var := expr`` through every atom (Hoare assignment).

    ``a*y + b <rel> c`` reduces to a single atom on ``y`` (or a constant
    verdict) because ``expr`` is affine in one variable.
    """
    _check_name(var, "var")
    if not isinstance(expr, LinExpr):
        raise HoareLogicError("expr must be a LinExpr")
    if not isinstance(assertion, Assertion):
        raise HoareLogicError("assertion must be an Assertion")
    out: List[Atom] = []
    for atom in assertion.atoms:
        if atom.var != var:
            out.append(atom)
            continue
        a, b, rel, c = expr.coeff, expr.const, atom.rel, atom.bound
        if expr.var is None or a == 0:
            # constant expression: the atom collapses to a verdict
            verdict = _eval_const(b, rel, c)
            if not verdict:
                return FALSE_ATOM_WRAPPER  # whole conjunction is false
            continue  # True atom drops out
        if a < 0:  # multiply through by -1, flip the relation
            a, b, c, rel = -a, -b, -c, _FLIP[rel]
        y = expr.var
        if rel == "==":
            if (c - b) % a == 0:
                out.append(Atom(y, "==", (c - b) // a))
            else:
                return FALSE_ATOM_WRAPPER
        elif rel == "!=":
            if (c - b) % a == 0:
                out.append(Atom(y, "!=", (c - b) // a))
            # else: always true, drops out
        elif rel == "<=":
            out.append(Atom(y, "<=", (c - b) // a))
        elif rel == "<":
            out.append(Atom(y, "<=", (c - b - 1) // a))
        elif rel == ">=":
            out.append(Atom(y, ">=", _ceil_div(c - b, a)))
        elif rel == ">":
            out.append(Atom(y, ">", (c - b) // a))
    return Assertion.of(out)


def _eval_const(value: int, rel: str, bound: int) -> bool:
    return {
        "==": value == bound,
        "!=": value != bound,
        "<": value < bound,
        "<=": value <= bound,
        ">": value > bound,
        ">=": value >= bound,
    }[rel]


class _FalseAssertion(Assertion):
    """Sentinel for a refuted conjunction (substitution hit False)."""

    def __init__(self) -> None:
        object.__setattr__(self, "atoms", frozenset())

    def conjoin(self, other: "Assertion | Atom") -> "Assertion":
        return self

    def as_dict(self) -> Dict[str, Any]:
        return {"false": True}


FALSE_ATOM_WRAPPER: Assertion = _FalseAssertion()


# ---------------------------------------------------------------------------
# Entailment over the linear fragment
# ---------------------------------------------------------------------------

def _bounds(hyps: Assertion) -> Tuple[Dict[str, int], Dict[str, int],
                                      Dict[str, int], Dict[str, FrozenSet[int]],
                                      bool]:
    """Collect per-variable equalities, inclusive bounds, disequalities.

    Returns (eq, lo, hi, diseq, contradiction).
    """
    eq: Dict[str, int] = {}
    lo: Dict[str, int] = {}
    hi: Dict[str, int] = {}
    diseq: Dict[str, FrozenSet[int]] = {}
    for atom in hyps.atoms:
        v, r, c = atom.var, atom.rel, atom.bound
        if r == "==":
            if v in eq and eq[v] != c:
                return eq, lo, hi, diseq, True
            eq[v] = c
        elif r == "!=":
            diseq[v] = diseq.get(v, frozenset()) | {c}
        elif r in (">=", ">"):
            cand = c if r == ">=" else c + 1
            lo[v] = max(lo.get(v, cand), cand)
        else:  # <=, <
            cand = c if r == "<=" else c - 1
            hi[v] = min(hi.get(v, cand), cand)
    for v, c in eq.items():
        if v in lo and lo[v] > c:
            return eq, lo, hi, diseq, True
        if v in hi and hi[v] < c:
            return eq, lo, hi, diseq, True
        if c in diseq.get(v, frozenset()):
            return eq, lo, hi, diseq, True
    for v in lo:
        if v in hi and lo[v] > hi[v]:
            return eq, lo, hi, diseq, True
        # a collapsed interval is an equality
        if v in hi and lo[v] == hi[v] and v not in eq:
            eq[v] = lo[v]
    return eq, lo, hi, diseq, False


def implies(hyps: Assertion, goal: Assertion) -> bool:
    """Decide ``hyps |= goal`` inside the linear-integer fragment.

    Sound: every accepted implication holds over the integers.
    Incomplete by design: the fragment is small on purpose.
    """
    if not isinstance(hyps, Assertion) or not isinstance(goal, Assertion):
        raise HoareLogicError("implies takes Assertion arguments")
    eq, lo, hi, diseq, contradiction = _bounds(hyps)
    if contradiction:
        return True  # ex falso, even into an explicit False goal
    if isinstance(goal, _FalseAssertion):
        return False  # no non-contradictory hyps entail False
    for atom in goal.atoms:
        v, r, c = atom.var, atom.rel, atom.bound
        if v in eq:
            val = eq[v]
            if not _eval_const(val, r, c):
                return False
            continue
        if r == "!=":
            if c in diseq.get(v, frozenset()):
                continue
            if v in lo and c < lo[v]:
                continue
            if v in hi and c > hi[v]:
                continue
            return False
        if r in ("<=", "<"):
            if v in hi and (hi[v] < c or (r == "<=" and hi[v] == c)):
                continue
            return False
        if r in (">=", ">"):
            if v in lo and (lo[v] > c or (r == ">=" and lo[v] == c)):
                continue
            return False
        # "==" with no equality info
        return False
    return True


# ---------------------------------------------------------------------------
# Programs
# ---------------------------------------------------------------------------

class Command:
    """Base class for the tiny imperative language."""

    def as_dict(self) -> Dict[str, Any]:
        raise NotImplementedError


@dataclass(frozen=True)
class Skip(Command):
    def as_dict(self) -> Dict[str, Any]:
        return {"cmd": "skip"}


@dataclass(frozen=True)
class Assign(Command):
    var: str
    expr: LinExpr

    def __post_init__(self) -> None:
        _check_name(self.var, "var")
        if not isinstance(self.expr, LinExpr):
            raise HoareLogicError("expr must be a LinExpr")

    def as_dict(self) -> Dict[str, Any]:
        return {"cmd": "assign", "var": self.var, "expr": self.expr.as_dict()}


@dataclass(frozen=True)
class Seq(Command):
    first: Command
    second: Command

    def __post_init__(self) -> None:
        for part in (self.first, self.second):
            if not isinstance(part, Command):
                raise HoareLogicError("Seq parts must be Commands")

    def as_dict(self) -> Dict[str, Any]:
        return {"cmd": "seq", "first": self.first.as_dict(),
                "second": self.second.as_dict()}


@dataclass(frozen=True)
class If(Command):
    cond: Atom
    then_branch: Command
    else_branch: Command

    def __post_init__(self) -> None:
        if not isinstance(self.cond, Atom):
            raise HoareLogicError("If condition must be a single Atom")
        for part in (self.then_branch, self.else_branch):
            if not isinstance(part, Command):
                raise HoareLogicError("If branches must be Commands")

    def as_dict(self) -> Dict[str, Any]:
        return {"cmd": "if", "cond": self.cond.as_dict(),
                "then": self.then_branch.as_dict(),
                "else": self.else_branch.as_dict()}


@dataclass(frozen=True)
class While(Command):
    cond: Atom
    inv: Assertion
    body: Command

    def __post_init__(self) -> None:
        if not isinstance(self.cond, Atom):
            raise HoareLogicError("While condition must be a single Atom")
        if not isinstance(self.inv, Assertion):
            raise HoareLogicError("While invariant must be an Assertion")
        if not isinstance(self.body, Command):
            raise HoareLogicError("While body must be a Command")

    def as_dict(self) -> Dict[str, Any]:
        return {"cmd": "while", "cond": self.cond.as_dict(),
                "inv": self.inv.as_dict(), "body": self.body.as_dict()}


# ---------------------------------------------------------------------------
# Verification conditions, triples, reports
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VC:
    """One verification condition: ``hyps |= goal``."""

    kind: str
    hyps: Assertion
    goal: Assertion

    def discharged(self) -> bool:
        return implies(self.hyps, self.goal)

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "hyps": self.hyps.as_dict(),
                "goal": self.goal.as_dict()}


@dataclass(frozen=True)
class HoareTriple:
    """A pinned ``{pre} prog {post}`` record."""

    pre: Assertion
    prog: Command
    post: Assertion

    def __post_init__(self) -> None:
        for name, value, kind in (("pre", self.pre, Assertion),
                                 ("prog", self.prog, Command),
                                 ("post", self.post, Assertion)):
            if not isinstance(value, kind):
                raise HoareLogicError(f"{name} has the wrong type")

    def digest(self) -> str:
        return "sha256:" + jcs_sha256_hex({
            "version": HOARE_LOGIC_VERSION,
            "pre": self.pre.as_dict(),
            "prog": self.prog.as_dict(),
            "post": self.post.as_dict(),
        })

    def as_dict(self) -> Dict[str, Any]:
        return {"version": HOARE_LOGIC_VERSION, "schema": HOARE_LOGIC_SCHEMA,
                "pre": self.pre.as_dict(), "prog": self.prog.as_dict(),
                "post": self.post.as_dict(), "digest": self.digest()}


@dataclass(frozen=True)
class ProofNode:
    """One proof-rule application: rule name + premise digests."""

    rule: str
    premises: Tuple[str, ...]
    triple_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"rule": self.rule, "premises": list(self.premises),
                "triple": self.triple_digest}


@dataclass(frozen=True)
class TripleCheck:
    """Result of checking (or proving) a triple."""

    triple: HoareTriple
    verified: bool
    vcs: Tuple[VC, ...] = ()
    failed: Tuple[int, ...] = ()
    proof: Optional[ProofNode] = None

    def as_dict(self) -> Dict[str, Any]:
        return {"triple": self.triple.as_dict(), "verified": self.verified,
                "vcs": [vc.as_dict() for vc in self.vcs],
                "failed": list(self.failed),
                "proof": self.proof.as_dict() if self.proof else None}


def _wp(cmd: Command, post: Assertion) -> Assertion:
    """Weakest precondition through straight-line code (loops use inv)."""
    if isinstance(cmd, Skip):
        return post
    if isinstance(cmd, Assign):
        return substitute(post, cmd.var, cmd.expr)
    if isinstance(cmd, Seq):
        return _wp(cmd.first, _wp(cmd.second, post))
    if isinstance(cmd, If):
        left = _wp(cmd.then_branch, post).conjoin(cmd.cond)
        right = _wp(cmd.else_branch, post).conjoin(cmd.cond.negate())
        return left.conjoin(right)
    if isinstance(cmd, While):
        return cmd.inv
    raise HoareLogicError(f"unknown command {type(cmd).__name__}")


def _vcs(pre: Assertion, cmd: Command, post: Assertion) -> List[VC]:
    """Generate verification conditions for ``{pre} cmd {post}``."""
    if isinstance(cmd, Skip):
        return [VC("skip", pre, post)]
    if isinstance(cmd, Assign):
        return [VC("assign", pre, substitute(post, cmd.var, cmd.expr))]
    if isinstance(cmd, Seq):
        mid = _wp(cmd.second, post)
        return _vcs(pre, cmd.first, mid) + _vcs(mid, cmd.second, post)
    if isinstance(cmd, If):
        return (_vcs(pre.conjoin(cmd.cond), cmd.then_branch, post)
                + _vcs(pre.conjoin(cmd.cond.negate()), cmd.else_branch, post))
    if isinstance(cmd, While):
        inv, cond = cmd.inv, cmd.cond
        return ([VC("loop-entry", pre, inv)]
                + _vcs(inv.conjoin(cond), cmd.body, inv)
                + [VC("loop-exit", inv.conjoin(cond.negate()), post)])
    raise HoareLogicError(f"unknown command {type(cmd).__name__}")


# ---------------------------------------------------------------------------
# The verifier: VCG checking plus the textbook proof rules
# ---------------------------------------------------------------------------

class HoareLogic:
    """Hoare-logic triple checking and rule application."""

    # -- automated checking (VCG) --------------------------------------

    def triple(self, pre: Assertion, prog: Command, post: Assertion) -> TripleCheck:
        """Check ``{pre} prog {post}`` by generating and discharging VCs."""
        t = HoareTriple(pre, prog, post)
        vcs = tuple(_vcs(pre, prog, post))
        failed = tuple(i for i, vc in enumerate(vcs) if not vc.discharged())
        return TripleCheck(triple=t, verified=not failed, vcs=vcs,
                           failed=failed)

    # -- axioms --------------------------------------------------------

    def skip_axiom(self, post: Assertion) -> TripleCheck:
        """``{Q} skip {Q}`` holds by construction."""
        t = HoareTriple(post, Skip(), post)
        return TripleCheck(triple=t, verified=True,
                           proof=ProofNode("skip-axiom", (), t.digest()))

    def assign_axiom(self, var: str, expr: LinExpr,
                     post: Assertion) -> TripleCheck:
        """``{Q[e/x]} x := e {Q}`` holds by construction."""
        pre = substitute(post, var, expr)
        t = HoareTriple(pre, Assign(var, expr), post)
        return TripleCheck(triple=t, verified=True,
                           proof=ProofNode("assign-axiom", (), t.digest()))

    # -- proof rules ---------------------------------------------------

    @staticmethod
    def _require_verified(check: TripleCheck, name: str) -> HoareTriple:
        if not isinstance(check, TripleCheck):
            raise RuleApplicationError(f"{name}: premise is not a TripleCheck")
        if not check.verified:
            raise RuleApplicationError(f"{name}: premise is not verified")
        return check.triple

    def sequence_rule(self, first: TripleCheck,
                      second: TripleCheck) -> TripleCheck:
        """``{P} C1 {R}, {R} C2 {Q}  |-  {P} C1;C2 {Q}``."""
        t1 = self._require_verified(first, "sequence_rule(first)")
        t2 = self._require_verified(second, "sequence_rule(second)")
        if t1.post != t2.pre:
            raise RuleApplicationError(
                "sequence_rule: middle assertions differ "
                f"({t1.post.as_dict()} != {t2.post.as_dict()})")
        t = HoareTriple(t1.pre, Seq(t1.prog, t2.prog), t2.post)
        proof = ProofNode("sequence", (t1.digest(), t2.digest()), t.digest())
        return TripleCheck(triple=t, verified=True, proof=proof)

    def if_rule(self, then_check: TripleCheck, else_check: TripleCheck,
                cond: Atom, pre: Assertion) -> TripleCheck:
        """``{P^B} C1 {Q}, {P^~B} C2 {Q}  |-  {P} if B {Q}``."""
        t1 = self._require_verified(then_check, "if_rule(then)")
        t2 = self._require_verified(else_check, "if_rule(else)")
        if not isinstance(cond, Atom):
            raise RuleApplicationError("if_rule: cond must be an Atom")
        if not isinstance(pre, Assertion):
            raise RuleApplicationError("if_rule: pre must be an Assertion")
        if t1.pre != pre.conjoin(cond):
            raise RuleApplicationError("if_rule: then-premise mismatch")
        if t2.pre != pre.conjoin(cond.negate()):
            raise RuleApplicationError("if_rule: else-premise mismatch")
        if t1.post != t2.post:
            raise RuleApplicationError("if_rule: postconditions differ")
        t = HoareTriple(pre, If(cond, t1.prog, t2.prog), t1.post)
        proof = ProofNode("if", (t1.digest(), t2.digest()), t.digest())
        return TripleCheck(triple=t, verified=True, proof=proof)

    def loop_rule(self, body_check: TripleCheck, inv: Assertion,
                  cond: Atom, post: Assertion) -> TripleCheck:
        """``{I^B} C {I}, (I^~B) => Q  |-  {I} while B {Q}``."""
        tb = self._require_verified(body_check, "loop_rule(body)")
        for name, value, kind in (("inv", inv, Assertion),
                                 ("cond", cond, Atom),
                                 ("post", post, Assertion)):
            if not isinstance(value, kind):
                raise RuleApplicationError(f"loop_rule: {name} wrong type")
        if tb.pre != inv.conjoin(cond):
            raise RuleApplicationError("loop_rule: body pre must be I ^ B")
        if tb.post != inv:
            raise RuleApplicationError("loop_rule: body post must be I")
        if not implies(inv.conjoin(cond.negate()), post):
            raise RuleApplicationError(
                "loop_rule: (I ^ ~B) => Q does not hold in the fragment")
        t = HoareTriple(inv, While(cond, inv, tb.prog), post)
        proof = ProofNode("while", (tb.digest(),), t.digest())
        return TripleCheck(triple=t, verified=True, proof=proof)

    def consequence_rule(self, check: TripleCheck, pre: Assertion,
                         post: Assertion) -> TripleCheck:
        """``P' => P, {P} C {Q}, Q => Q'  |-  {P'} C {Q'}``."""
        t = self._require_verified(check, "consequence_rule")
        if not isinstance(pre, Assertion) or not isinstance(post, Assertion):
            raise RuleApplicationError(
                "consequence_rule: pre/post must be Assertions")
        if not implies(pre, t.pre):
            raise RuleApplicationError(
                "consequence_rule: new pre does not imply old pre")
        if not implies(t.post, post):
            raise RuleApplicationError(
                "consequence_rule: old post does not imply new post")
        new = HoareTriple(pre, t.prog, post)
        proof = ProofNode("consequence", (t.digest(),), new.digest())
        return TripleCheck(triple=new, verified=True, proof=proof)

    # -- audit ----------------------------------------------------------

    def hoare_logic_audit_event(self, kind: str, seq: int,
                                check: Optional[TripleCheck] = None) -> dict:
        """Shape a verifier lifecycle event as an ``audit.ndjson/1`` record.

        ``kind`` is one of ``triple-checked`` / ``triple-failed`` /
        ``rule-applied`` / ``rule-rejected``.
        """
        valid = ("triple-checked", "triple-failed", "rule-applied",
                 "rule-rejected")
        if kind not in valid:
            raise HoareLogicError(f"unknown audit kind {kind!r}")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise HoareLogicError("seq must be a non-negative int")
        record = {
            "schema": "audit.ndjson/1",
            "kind": f"hoare-logic.{kind}",
            "module": HOARE_LOGIC_SCHEMA,
            "version": HOARE_LOGIC_VERSION,
            "seq": seq,
        }
        if check is not None:
            if not isinstance(check, TripleCheck):
                raise HoareLogicError("check must be a TripleCheck")
            record["triple_digest"] = check.triple.digest()
            record["verified"] = check.verified
        return record


def main() -> None:
    hl = HoareLogic()
    x0 = Assertion.of([Atom("x", "==", 0)])
    x1 = Assertion.of([Atom("x", "==", 1)])
    inc = Assign("x", LinExpr(1, "x", 1))
    check = hl.triple(x0, inc, x1)
    assert check.verified, f"VCG failed: {check.failed}"

    # sequence rule: x:=x+1 twice, 0 -> 2
    t1 = hl.assign_axiom("x", LinExpr(1, "x", 1), x1)
    t2 = hl.assign_axiom("x", LinExpr(1, "x", 1),
                         Assertion.of([Atom("x", "==", 2)]))
    seq = hl.sequence_rule(t1, t2)
    assert seq.verified and seq.triple.post == Assertion.of([Atom("x", "==", 2)])

    # loop rule: while x < 10 with invariant x >= 0
    inv = Assertion.of([Atom("x", ">=", 0)])
    cond = Atom("x", "<", 10)
    body = hl.triple(inv.conjoin(cond), inc, inv)
    assert body.verified, f"loop body VCs failed: {body.failed}"
    loop = hl.loop_rule(body, inv, cond, inv)
    assert loop.verified

    ev = hl.hoare_logic_audit_event("triple-checked", 0, check)
    assert ev["schema"] == "audit.ndjson/1"
    print("hoare-logic OK: VCG, sequence rule, loop rule, audit")


if __name__ == "__main__":
    main()
