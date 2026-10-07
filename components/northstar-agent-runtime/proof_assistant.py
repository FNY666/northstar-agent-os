"""Interactive theorem proving: session bookkeeping for goal-driven proofs.

Coq/Lean-style interactive proof: the user states a goal, then applies
tactics (``intro``, ``apply``, ``rewrite``, ...) that transform goals into
subgoals until none remain, at which point ``qed()`` mints a certificate.
The same vocabulary also covers the degenerate cases: ``admit()`` closes
a goal by admission (tainting the certificate), ``clear()`` drops a
hypothesis, and the proof script is an append-only audit trail.

Propositions live in a tiny term language::

    expr := name | f(x) | A -> B | A /\\ B | A \\/ B | x = y
          | forall x, P | exists x, P | ( expr )

The parser and pretty-printer round-trip exactly
(``parse(print(e)) == e``), so tactics cannot silently mangle
propositions. ``intro`` moves an implication antecedent (or a ``forall``
binder) into the hypothesis context; ``apply`` discharges a goal from a
matching hypothesis or peels implications whose conclusion matches;
``rewrite`` substitutes an equational hypothesis through the goal;
``qed`` refuses to close while goals remain.

Honest scope: this is *session bookkeeping*, not a proof checker. Goal
transformations are shallow syntactic matches on a tiny language; a
``qed()`` certificate means "this session closed all its goals through
the recorded tactics", never "the theorem is true". In particular it
does not check that the *host's* propositions are well-formed in any
ambient logic, does not implement unification (``apply`` needs the
conclusion to match the goal structurally), and capture-avoiding
substitution is documented as a known limitation -- binders are
single-sort and substitution is naive. Real proof checking (Coq, Lean,
Isabelle) drops in at the call sites without changing the session API.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union


#: Version pin for this module's record shape.
PROOF_ASSISTANT_VERSION = "proof-assistant.v1"

#: Schema pin carried on audit records.
PROOF_ASSISTANT_SCHEMA = "northstar.proof-assistant.v1"

#: Domain-separation prefix so digest pins cannot collide with other modules.
_DOMAIN = b"northstar.proof-assistant.v1:"

#: Fixed audit vocabulary.
_TACTIC_KINDS = frozenset(
    {
        "goal-set",
        "intro",
        "apply",
        "rewrite",
        "exact",
        "assumption",
        "split",
        "left",
        "right",
        "clear",
        "admit",
    }
)

#: Fixed audit-event vocabulary.
_EVENT_KINDS = frozenset({"goal-set", "tactic", "qed", "rejected"})


class ProofError(Exception):
    """Raised for malformed goals/tactics or unclosed proofs. Fail-closed."""


# ---------------------------------------------------------------------------
# Proposition language
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Expr:
    """A proposition/term in the tiny proof language."""

    kind: str  # "var" | "app" | "imp" | "and" | "or" | "eq" | "forall" | "exists"
    name: str = ""
    left: Optional["Expr"] = None
    right: Optional["Expr"] = None
    var: str = ""
    body: Optional["Expr"] = None

    def __post_init__(self) -> None:
        allowed = {"var", "app", "imp", "and", "or", "eq", "forall", "exists"}
        if self.kind not in allowed:
            raise ProofError(f"bad expr kind: {self.kind!r}")
        if self.kind == "var" and not self.name:
            raise ProofError("var needs a name")
        if self.kind == "app" and (self.left is None or self.right is None):
            raise ProofError("app needs fn and arg")
        if self.kind in ("imp", "and", "or", "eq") and (
            self.left is None or self.right is None
        ):
            raise ProofError(f"{self.kind} needs left and right")
        if self.kind in ("forall", "exists") and (not self.var or self.body is None):
            raise ProofError(f"{self.kind} needs var and body")


def Var(name: str) -> Expr:
    """Atomic proposition / term variable."""
    _require_name(name, "var name")
    return Expr(kind="var", name=name)


def App(fn: Expr, arg: Expr) -> Expr:
    """Function application: ``P x``."""
    if not isinstance(fn, Expr) or not isinstance(arg, Expr):
        raise ProofError("app needs Expr fn and arg")
    return Expr(kind="app", left=fn, right=arg)


def Imp(lhs: Expr, rhs: Expr) -> Expr:
    """Implication: ``A -> B``."""
    _need_expr(lhs, rhs)
    return Expr(kind="imp", left=lhs, right=rhs)


def And_(lhs: Expr, rhs: Expr) -> Expr:
    """Conjunction: ``A /\\ B``."""
    _need_expr(lhs, rhs)
    return Expr(kind="and", left=lhs, right=rhs)


def Or_(lhs: Expr, rhs: Expr) -> Expr:
    """Disjunction: ``A \\/ B``."""
    _need_expr(lhs, rhs)
    return Expr(kind="or", left=lhs, right=rhs)


def Eq(lhs: Expr, rhs: Expr) -> Expr:
    """Equality: ``x = y``."""
    _need_expr(lhs, rhs)
    return Expr(kind="eq", left=lhs, right=rhs)


def ForAll(var: str, body: Expr) -> Expr:
    """Universal quantification: ``forall x, P``."""
    _require_name(var, "binder")
    if not isinstance(body, Expr):
        raise ProofError("forall body must be Expr")
    return Expr(kind="forall", var=var, body=body)


def Exists(var: str, body: Expr) -> Expr:
    """Existential quantification: ``exists x, P``."""
    _require_name(var, "binder")
    if not isinstance(body, Expr):
        raise ProofError("exists body must be Expr")
    return Expr(kind="exists", var=var, body=body)


_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_']*$")


def _require_name(value: object, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not _NAME_RE.match(value):
        raise ProofError(f"{what} must be a bare name, got {value!r}")
    return value


def _need_expr(*exprs: object) -> None:
    for e in exprs:
        if not isinstance(e, Expr):
            raise ProofError(f"expected Expr, got {type(e).__name__}")


# --- pretty printer ---------------------------------------------------------


def _print(e: Expr) -> str:
    """Parenthesized printer; every non-atom is wrapped, so output parses
    back unambiguously."""
    k = e.kind
    if k == "var":
        return e.name
    if k == "app":
        return f"({_print(e.left)} {_print(e.right)})"
    if k == "imp":
        return f"({_print(e.left)} -> {_print(e.right)})"
    if k == "and":
        return f"({_print(e.left)} /\\ {_print(e.right)})"
    if k == "or":
        return f"({_print(e.left)} \\/ {_print(e.right)})"
    if k == "eq":
        return f"({_print(e.left)} = {_print(e.right)})"
    if k == "forall":
        return f"(forall {e.var}, {_print(e.body)})"
    if k == "exists":
        return f"(exists {e.var}, {_print(e.body)})"
    raise ProofError(f"cannot print {k}")


def print_expr(e: Expr) -> str:
    """Render an expression to its canonical textual form."""
    if not isinstance(e, Expr):
        raise ProofError(f"expected Expr, got {type(e).__name__}")
    return _print(e)


# --- parser -----------------------------------------------------------------


_TOKEN_RE = re.compile(
    r"\s*(?:(->)|(/\\)|(\\/)|(=)|(\()|(\))|(,)|([A-Za-z_][A-Za-z0-9_']*))"
)


class _Parser:
    def __init__(self, text: str) -> None:
        self._toks: List[str] = []
        for m in _TOKEN_RE.finditer(text):
            tok = next(g for g in m.groups() if g is not None)
            self._toks.append(tok)
        # Anything not consumed by the token regex is a syntax error.
        stripped = _TOKEN_RE.sub("", text)
        if stripped.strip():
            raise ProofError(f"bad syntax near {stripped.strip()!r}")
        self._pos = 0

    def _peek(self) -> Optional[str]:
        return self._toks[self._pos] if self._pos < len(self._toks) else None

    def _next(self) -> str:
        tok = self._peek()
        if tok is None:
            raise ProofError("unexpected end of proposition")
        self._pos += 1
        return tok

    def _expect(self, tok: str) -> None:
        got = self._next()
        if got != tok:
            raise ProofError(f"expected {tok!r}, got {got!r}")

    def parse(self) -> Expr:
        e = self._parse_imp()
        if self._peek() is not None:
            raise ProofError(f"trailing token {self._peek()!r}")
        return e

    # Precedence, loosest to tightest:  ->  <  \/  <  /\  <  =  <  application.
    # So ``A -> B \/ C`` is ``A -> (B \/ C)`` and ``A /\ B -> C`` is
    # ``(A /\ B) -> C``, matching Coq's notation levels.

    def _parse_imp(self) -> Expr:
        lhs = self._parse_or()
        if self._peek() == "->":
            self._next()
            return Imp(lhs, self._parse_imp())  # right associative
        return lhs

    def _parse_or(self) -> Expr:
        lhs = self._parse_and()
        while self._peek() == "\\/":
            self._next()
            lhs = Or_(lhs, self._parse_and())
        return lhs

    def _parse_and(self) -> Expr:
        lhs = self._parse_eq()
        while self._peek() == "/\\":
            self._next()
            lhs = And_(lhs, self._parse_eq())
        return lhs

    def _parse_eq(self) -> Expr:
        lhs = self._parse_app()
        if self._peek() == "=":
            self._next()
            return Eq(lhs, self._parse_app())
        return lhs

    def _parse_app(self) -> Expr:
        fn = self._parse_atom()
        while True:
            nxt = self._peek()
            if nxt is None or nxt in (")", ",", "->", "/\\", "\\/", "="):
                return fn
            fn = App(fn, self._parse_atom())

    def _parse_atom(self) -> Expr:
        tok = self._peek()
        if tok == "(":
            self._next()
            e = self._parse_imp()
            self._expect(")")
            return e
        if tok in ("forall", "exists"):
            self._next()
            var = self._next()
            _require_name(var, "binder")
            self._expect(",")
            body = self._parse_imp()
            return ForAll(var, body) if tok == "forall" else Exists(var, body)
        if tok is None or tok in ("->", "/\\", "\\/", "=", ",", ")"):
            raise ProofError(f"unexpected token {tok!r}")
        self._next()
        return Var(tok)


def parse_expr(text: str) -> Expr:
    """Parse a proposition in the tiny syntax. Fail-closed on bad input."""
    if isinstance(text, bool) or not isinstance(text, str) or not text.strip():
        raise ProofError("proposition must be a non-empty string")
    return _Parser(text).parse()


# --- substitution / rewriting -----------------------------------------------


def subst(e: Expr, var: str, term: Expr) -> Expr:
    """Naive substitution of ``term`` for ``var`` in ``e``.

    Capture-avoidance is a documented limitation: binders shadowing
    ``var`` are left alone (the bound occurrence is renamed away from
    the substitution), but a free variable of ``term`` captured by a
    *different* binder of ``e`` is not renamed. Hosts with real
    binders must not rely on this for soundness.
    """
    _need_expr(e, term)
    _require_name(var, "var")
    k = e.kind
    if k == "var":
        return term if e.name == var else e
    if k == "app":
        return App(subst(e.left, var, term), subst(e.right, var, term))
    if k in ("imp", "and", "or", "eq"):
        return Expr(kind=k, left=subst(e.left, var, term), right=subst(e.right, var, term))
    if k in ("forall", "exists"):
        if e.var == var:
            return e  # shadowed: substitution stops here
        return Expr(kind=k, var=e.var, body=subst(e.body, var, term))
    raise ProofError(f"cannot substitute into {k}")


def rewrite_in(e: Expr, lhs: Expr, rhs: Expr) -> Expr:
    """Replace every occurrence of ``lhs`` in ``e`` with ``rhs``."""
    _need_expr(e, lhs, rhs)
    if e == lhs:
        return rhs
    k = e.kind
    if k == "var":
        return e
    if k == "app":
        return App(rewrite_in(e.left, lhs, rhs), rewrite_in(e.right, lhs, rhs))
    if k in ("imp", "and", "or", "eq"):
        return Expr(
            kind=k,
            left=rewrite_in(e.left, lhs, rhs),
            right=rewrite_in(e.right, lhs, rhs),
        )
    if k in ("forall", "exists"):
        return Expr(kind=k, var=e.var, body=rewrite_in(e.body, lhs, rhs))
    raise ProofError(f"cannot rewrite into {k}")


def _pin_expr(e: Expr) -> str:
    return "sha256:" + hashlib.sha256(_DOMAIN + _print(e).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Session records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TacticRecord:
    """One applied tactic: name, arguments, resulting goal pins."""

    name: str
    args: Tuple[str, ...]
    goals_after: Tuple[str, ...]
    seq: int

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "args": list(self.args),
            "goals_after": list(self.goals_after),
            "seq": self.seq,
            "version": PROOF_ASSISTANT_VERSION,
            "schema": PROOF_ASSISTANT_SCHEMA,
        }


@dataclass(frozen=True)
class ProofCertificate:
    """Minted by ``qed()`` when (and only when) no goals remain."""

    goal: str  # pin of the original goal
    tactic_count: int
    tactics_digest: str  # pin over the tactic log
    admitted: bool  # True if any goal was closed by admit()
    seq: int

    def as_dict(self) -> dict:
        return {
            "goal": self.goal,
            "tactic_count": self.tactic_count,
            "tactics_digest": self.tactics_digest,
            "admitted": self.admitted,
            "seq": self.seq,
            "version": PROOF_ASSISTANT_VERSION,
            "schema": PROOF_ASSISTANT_SCHEMA,
        }


def proof_assistant_audit_event(kind: str, seq: int, **fields: object) -> dict:
    """Shape an ``audit.ndjson/1``-style record for a proof-session event."""
    if kind not in _EVENT_KINDS:
        raise ProofError(f"unknown event kind {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ProofError("seq must be a non-negative int")
    for key, value in fields.items():
        if not isinstance(value, (str, int, bool, list, dict)):
            raise ProofError(f"bad field {key!r}: {type(value).__name__}")
    return {
        "schema": "audit.ndjson/1",
        "module": PROOF_ASSISTANT_SCHEMA,
        "kind": kind,
        "seq": seq,
        **fields,
    }


# ---------------------------------------------------------------------------
# ProofAssistant
# ---------------------------------------------------------------------------


class ProofAssistant:
    """Goal-driven interactive proof session (simulated).

    Usage::

        pa = ProofAssistant().goal("A -> B -> A")
        pa.intro("hA").intro("hB")
        cert = pa.apply("hA").qed(0)

    Tactics return ``self`` so scripts chain. Every tactic appends a
    :class:`TacticRecord` to the log; ``qed`` fails closed while goals
    remain.
    """

    def __init__(self) -> None:
        self._goals: List[Expr] = []
        self._hyps: Dict[str, Expr] = {}
        self._tactics: List[TacticRecord] = []
        self._original_goal: Optional[Expr] = None
        self._admitted = False
        self._seq = 0
        self._auto = 0

    # -- session setup ------------------------------------------------------

    def goal(self, prop: Union[str, Expr]) -> "ProofAssistant":
        """Start (or restart) a proof of ``prop``."""
        e = parse_expr(prop) if isinstance(prop, str) else prop
        _need_expr(e)
        self._goals = [e]
        self._hyps = {}
        self._tactics = []
        self._original_goal = e
        self._admitted = False
        self._seq = 0
        self._auto = 0
        self._log("goal-set", (_print(e),))
        return self

    # -- views --------------------------------------------------------------

    def goals(self) -> Tuple[Expr, ...]:
        """Current goal stack (top goal last)."""
        return tuple(self._goals)

    def hypotheses(self) -> Dict[str, Expr]:
        """Hypothesis context (copy)."""
        return dict(self._hyps)

    def tactic_log(self) -> Tuple[TacticRecord, ...]:
        """Append-only tactic log."""
        return tuple(self._tactics)

    def admitted(self) -> bool:
        """Whether any goal was closed by admission."""
        return self._admitted

    # -- internals ----------------------------------------------------------

    def _top(self) -> Expr:
        if not self._goals:
            raise ProofError("no goals: tactic applied to an empty goal stack")
        return self._goals[-1]

    def _auto_name(self, base: str) -> str:
        while True:
            name = f"{base}{self._auto}"
            self._auto += 1
            if name not in self._hyps:
                return name

    def _log(self, name: str, args: Tuple[str, ...]) -> None:
        self._seq += 1
        self._tactics.append(
            TacticRecord(
                name=name,
                args=args,
                goals_after=tuple(_print(g) for g in self._goals),
                seq=self._seq,
            )
        )

    def _hyp(self, name: str) -> Expr:
        _require_name(name, "hypothesis name")
        try:
            return self._hyps[name]
        except KeyError:
            raise ProofError(f"unknown hypothesis {name!r}") from None

    # -- tactics ------------------------------------------------------------

    def intro(self, name: Optional[str] = None) -> "ProofAssistant":
        """``A -> B`` becomes goal ``B`` with ``A`` hypothesized;
        ``forall x, P`` introduces a fresh parameter for ``x``."""
        top = self._top()
        if top.kind == "imp":
            hyp_name = (
                self._auto_name("H") if name is None else _require_name(name, "name")
            )
            if hyp_name in self._hyps:
                raise ProofError(f"hypothesis {hyp_name!r} already exists")
            self._hyps[hyp_name] = top.left
            self._goals[-1] = top.right
            self._log("intro", (hyp_name,))
            return self
        if top.kind == "forall":
            fresh = self._auto_name(top.var + "_")
            self._goals[-1] = subst(top.body, top.var, Var(fresh))
            self._log("intro", (fresh,))
            return self
        raise ProofError(f"intro needs an implication or forall goal, got {top.kind}")

    def apply(self, name: str) -> "ProofAssistant":
        """Use hypothesis ``name`` against the goal.

        Exact match closes the goal; an ``A -> B`` (possibly curried)
        hypothesis whose conclusion matches the goal structurally turns
        each antecedent into a new subgoal.
        """
        top = self._top()
        hyp = self._hyp(name)
        if hyp == top:
            self._goals.pop()
            self._log("apply", (name,))
            return self
        # Peel leading implications while the conclusion matches the goal.
        cur, premises = hyp, []
        while cur.kind == "imp":
            premises.append(cur.left)
            cur = cur.right
        if cur == top and premises:
            self._goals.pop()
            # New subgoals pushed so the first premise is on top.
            for p in reversed(premises):
                self._goals.append(p)
            self._log("apply", (name,))
            return self
        raise ProofError(
            f"apply: hypothesis {name!r} does not match goal {_print(top)!r}"
        )

    def rewrite(self, name: str, direction: str = "lr") -> "ProofAssistant":
        """Rewrite the goal with equational hypothesis ``name``.

        ``direction="lr"`` replaces ``l`` by ``r``; ``"rl"`` the reverse.
        """
        if direction not in ("lr", "rl"):
            raise ProofError("direction must be 'lr' or 'rl'")
        hyp = self._hyp(name)
        if hyp.kind != "eq":
            raise ProofError(f"rewrite needs an equation hypothesis, got {hyp.kind}")
        lhs, rhs = (hyp.left, hyp.right) if direction == "lr" else (hyp.right, hyp.left)
        top = self._top()
        new = rewrite_in(top, lhs, rhs)
        if new == top:
            raise ProofError(f"rewrite: pattern {_print(lhs)!r} not found in goal")
        self._goals[-1] = new
        self._log("rewrite", (name, direction))
        return self

    def exact(self, name: str) -> "ProofAssistant":
        """Close the goal with a hypothesis that matches it exactly."""
        top = self._top()
        hyp = self._hyp(name)
        if hyp != top:
            raise ProofError(
                f"exact: {_print(hyp)!r} is not the goal {_print(top)!r}"
            )
        self._goals.pop()
        self._log("exact", (name,))
        return self

    def assumption(self) -> "ProofAssistant":
        """Close the goal if it appears among the hypotheses."""
        top = self._top()
        for hname, hexpr in self._hyps.items():
            if hexpr == top:
                self._goals.pop()
                self._log("assumption", (hname,))
                return self
        raise ProofError(f"assumption: goal {_print(top)!r} not in hypotheses")

    def split(self) -> "ProofAssistant":
        """``A /\\ B`` becomes two goals ``A`` and ``B`` (``A`` on top)."""
        top = self._top()
        if top.kind != "and":
            raise ProofError(f"split needs a conjunction goal, got {top.kind}")
        self._goals.pop()
        self._goals.append(top.right)
        self._goals.append(top.left)
        self._log("split", ())
        return self

    def left(self) -> "ProofAssistant":
        """``A \\/ B`` becomes goal ``A``."""
        top = self._top()
        if top.kind != "or":
            raise ProofError(f"left needs a disjunction goal, got {top.kind}")
        self._goals[-1] = top.left
        self._log("left", ())
        return self

    def right(self) -> "ProofAssistant":
        """``A \\/ B`` becomes goal ``B``."""
        top = self._top()
        if top.kind != "or":
            raise ProofError(f"right needs a disjunction goal, got {top.kind}")
        self._goals[-1] = top.right
        self._log("right", ())
        return self

    def clear(self, name: str) -> "ProofAssistant":
        """Drop hypothesis ``name`` from the context."""
        hyp = self._hyp(name)  # validates existence + name shape
        del self._hyps[name]
        self._log("clear", (name,))
        return self

    def admit(self) -> "ProofAssistant":
        """Close the current goal by admission. Taints the certificate."""
        self._top()  # fail-closed on empty stack
        self._goals.pop()
        self._admitted = True
        self._log("admit", ())
        return self

    def qed(self, seq: int) -> ProofCertificate:
        """Close the proof. Fails closed while any goal remains."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ProofError("seq must be a non-negative int")
        if self._goals:
            remaining = ", ".join(_print(g) for g in self._goals)
            raise ProofError(f"qed with {len(self._goals)} goal(s) remaining: {remaining}")
        if self._original_goal is None:
            raise ProofError("qed with no goal ever set")
        tactics_blob = "\n".join(
            f"{t.seq}:{t.name}({'|'.join(t.args)})" for t in self._tactics
        ).encode()
        digest = "sha256:" + hashlib.sha256(_DOMAIN + tactics_blob).hexdigest()
        return ProofCertificate(
            goal=_pin_expr(self._original_goal),
            tactic_count=len(self._tactics),
            tactics_digest=digest,
            admitted=self._admitted,
            seq=seq,
        )


def main() -> None:
    """Self-check: prove ``A -> B -> A`` and pin the certificate."""
    pa = (
        ProofAssistant()
        .goal("A -> B -> A")
        .intro("hA")
        .intro("hB")
        .apply("hA")
    )
    cert = pa.qed(0)
    assert cert.tactic_count == 4, cert.tactic_count  # goal-set + 2 intro + apply
    assert not cert.admitted
    # rewrite demo: x = y |- P x -> P y
    pa2 = ProofAssistant().goal("(x = y) -> (P x) -> (P y)")
    pa2.intro("heq").intro("hpx")
    pa2.rewrite("heq", "rl")  # goal (P y) becomes (P x)
    assert pa2.goals()[-1] == parse_expr("P x"), print_expr(pa2.goals()[-1])
    pa2.apply("hpx")
    cert2 = pa2.qed(1)
    assert cert2.tactic_count == 5, cert2.tactic_count
    print("proof-assistant OK: intro/apply/rewrite/qed, certificates pinned")


if __name__ == "__main__":
    main()
