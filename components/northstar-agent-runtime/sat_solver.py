"""Propositional SAT solver (DPLL, simulated CDCL bookkeeping absent).

Research motivation: SAT is the canonical NP-complete problem, and modern
CDCL solvers (MiniSat, Glucose, CaDiCaL) underpin hardware verification,
planning, and dependency resolution. The Davis-Putnam-Logemann-Loveland
(DPLL) procedure is the core: assign a variable, propagate forced
consequences, backtrack on conflict. This module pins the DPLL mechanics
in house style - deterministic, no wall-clock, stdlib-only - so the
runtime can use it for policy checks (e.g. "is this permission/ceiling
combination reachable?") without pulling in a solver dependency.

This module is the *solver* half. The host owns formula generation
(CNF encoding of the policy) and proof logging (DRAT - out of scope).

Algorithm (genuine DPLL, not a stub):

1. Preprocess: drop tautological clauses (x and -x in the same clause are
   always satisfied), reject empty clauses fail-fast (immediately UNSAT).
2. Unit propagation: while a clause is unit (exactly one unassigned
   literal), force it; if any clause is empty under the assignment,
   conflict - backtrack.
3. Pure-literal elimination: a literal whose negation never occurs can be
   set to satisfy all its clauses (sound, never harms satisfiability).
4. Branching: pick the lowest-numbered unassigned variable, try True then
   False (deterministic order - same formula always explores the same
   search tree on every machine).
5. Conflict learning is *not* implemented - this is DPLL, not CDCL
   (documented honest scope). The branching/depth bookkeeping exists so a
   real CDCL engine can drop in later without changing call sites.

CNF conventions:

- Variables are positive ints: 1, 2, 3, ...
- Literals are ints: +v means v true, -v means v false. 0 and bools are
  rejected fail-closed (``True`` is not variable 1).
- Clauses are sets of literals (duplicates collapse); a clause must be
  non-empty.
- ``SATSolver.solve()`` returns a frozen ``SolverResult``; ``model()``
  returns the winning assignment as ``{var: bool}`` or ``None``.

Honest scope:

- Sound and complete for the CNF it is given: a SAT verdict is backed by
  an independently checkable assignment (``verify_assignment``), and an
  UNSAT verdict means the search tree was exhausted.
- No conflict learning, no VSIDS, no restarts, no clause deletion - on
  adversarial formulas this is exponentially slower than CDCL. Do not
  treat it as a substitute for MiniSat/Glucose.
- Worst case is exponential time and stack depth. ``max_decisions`` is a
  caller-supplied budget; exceeding it returns a ``SolverResult`` with
  verdict ``unknown`` (fail-safe: never report SAT when unproven, never
  report UNSAT when unexplored).
- Caller-supplied int ``audit_seq`` values only. No wall-clock, no
  randomness, no I/O. Same formula, same decision order, every time.

Public API:

- ``SATSolver`` -- ``add_clause(*literals)``, ``add_clauses(iterable)``,
  ``solve(assumptions=(), max_decisions=None)``.
- ``SolverResult`` -- frozen record: ``verdict`` (``"sat"`` / ``"unsat"``
  / ``"unknown"``), ``assignment`` (tuple of signed literals, ``()`` when
  not SAT), ``decisions``, ``propagations``, ``n_vars``, ``n_clauses``,
  schema pin, ``as_dict()``.
- ``verify_assignment(assignment, clauses) -> bool`` -- independent check
  that an assignment satisfies a clause list.
- ``sat_solver_audit_event(kind, result, seq)`` -- ``audit.ndjson/1``
  shaped records (``solved-sat`` / ``solved-unsat`` / ``solve-unknown`` /
  ``clause-added``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

#: Version pin for the solver described here.
SAT_SOLVER_VERSION = "sat-solver.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.sat-solver.v1"

#: Verdict vocabulary for SolverResult.verdict.
VERDICTS = ("sat", "unsat", "unknown")

#: Fail-closed budget sanity bound: no caller may ask for more than this
#: many decisions in one solve call (guards the host, not the solver).
_MAX_DECISIONS_HARD_CAP = 10_000_000

#: Audit event kinds accepted by sat_solver_audit_event.
_AUDIT_KINDS = ("clause-added", "solved-sat", "solved-unsat", "solve-unknown")


class SATError(Exception):
    """Base error for SAT solver misuse."""


class EmptyClauseError(SATError):
    """An empty clause was added: the formula is immediately UNSAT."""


def _check_literal(lit: int) -> int:
    """Validate one literal; return it unchanged."""
    if isinstance(lit, bool) or not isinstance(lit, int):
        raise SATError(f"literal must be an int, got {type(lit).__name__}")
    if lit == 0:
        raise SATError("literal 0 is invalid (variables are 1-based)")
    return lit


def _check_seq(seq: int) -> int:
    """Validate a caller-supplied audit seq."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return seq


@dataclass(frozen=True)
class SolverResult:
    """Outcome of one solve call (immutable)."""

    verdict: str
    #: Winning assignment as signed literals (e.g. (1, -2, 3)); () unless sat.
    assignment: Tuple[int, ...] = ()
    #: Branching decisions taken (excluding propagated implications).
    decisions: int = 0
    #: Forced implications via unit propagation.
    propagations: int = 0
    #: Distinct variables in the formula.
    n_vars: int = 0
    #: Clauses in the formula (post-preprocessing count).
    n_clauses: int = 0

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise SATError(f"unknown verdict {self.verdict!r}")
        if self.verdict == "sat" and not self.assignment and self.n_vars > 0:
            raise SATError("SAT verdict on a non-trivial formula requires a non-empty assignment")
        if self.verdict != "sat" and self.assignment:
            raise SATError("assignment only valid with a SAT verdict")
        for lit in self.assignment:
            _check_literal(lit)
        # Assignment must be consistent: no var both signed ways.
        seen: Dict[int, int] = {}
        for lit in self.assignment:
            v = abs(lit)
            s = 1 if lit > 0 else -1
            if v in seen and seen[v] != s:
                raise SATError(f"inconsistent assignment for variable {v}")
            seen[v] = s
        for field in ("decisions", "propagations", "n_vars", "n_clauses"):
            val = getattr(self, field)
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise SATError(f"{field} must be a non-negative int")

    def model(self) -> Optional[Dict[int, bool]]:
        """Assignment as {var: bool}, or None when not SAT."""
        if self.verdict != "sat":
            return None
        return {abs(lit): lit > 0 for lit in self.assignment}

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "assignment": list(self.assignment),
            "decisions": self.decisions,
            "propagations": self.propagations,
            "n_vars": self.n_vars,
            "n_clauses": self.n_clauses,
            "version": SAT_SOLVER_VERSION,
            "schema": SCHEMA_PIN,
        }


def verify_assignment(assignment: Sequence[int], clauses: Sequence[Iterable[int]]) -> bool:
    """Independently check that an assignment satisfies every clause.

    Assignment: iterable of signed literals (the signed-var form used by
    SolverResult). A literal is satisfied if it appears in the assignment;
    a clause is satisfied if any literal is satisfied.
    """
    if not isinstance(assignment, (list, tuple)):
        raise SATError("assignment must be a list or tuple")
    assigned: Set[int] = set()
    for lit in assignment:
        assigned.add(_check_literal(lit))
    for clause in clauses:
        sat = False
        for lit in clause:
            if _check_literal(int(lit)) in assigned:
                sat = True
                break
        if not sat:
            return False
    return True


class SATSolver:
    """Incremental DPLL solver over a clause database.

    Clauses accumulate with ``add_clause``; ``solve`` may be called any
    number of times (assumptions do not pollute the stored formula).
    """

    def __init__(self) -> None:
        #: Stored clauses post-preprocessing (tautologies dropped).
        self._clauses: List[FrozenSet[int]] = []
        #: True once an empty clause (or equivalent) was seen.
        self._trivially_unsat = False

    # ------------------------------------------------------------------ #
    # Clause management                                                   #
    # ------------------------------------------------------------------ #

    def add_clause(self, *literals: int) -> "SATSolver":
        """Add one clause (a disjunction of literals). Tautologies are
        dropped as always-satisfied; empty clauses raise EmptyClauseError
        and poison the solver (every future solve is UNSAT)."""
        clause = self._validate_and_normalize(literals)
        if clause is None:
            # Tautology: always satisfied, nothing to store.
            return self
        if not clause:
            self._trivially_unsat = True
            raise EmptyClauseError("empty clause: formula is UNSAT")
        self._clauses.append(frozenset(clause))
        return self

    def add_clauses(self, clauses: Iterable[Iterable[int]]) -> "SATSolver":
        """Add several clauses at once."""
        for clause in clauses:
            self.add_clause(*clause)
        return self

    @staticmethod
    def _validate_and_normalize(literals: Iterable[int]) -> Optional[Set[int]]:
        """Validate literals; return None for tautologies, else the set."""
        seen: Set[int] = set()
        for lit in literals:
            lit = _check_literal(lit)  # no int() coercion: True/"1"/1.5 rejected
            if -lit in seen:
                return None  # tautology
            seen.add(lit)
        return seen

    # ------------------------------------------------------------------ #
    # Properties                                                          #
    # ------------------------------------------------------------------ #

    @property
    def n_clauses(self) -> int:
        return len(self._clauses)

    @property
    def n_vars(self) -> int:
        return len({abs(lit) for clause in self._clauses for lit in clause})

    @property
    def variables(self) -> Tuple[int, ...]:
        return tuple(sorted({abs(lit) for clause in self._clauses for lit in clause}))

    # ------------------------------------------------------------------ #
    # DPLL                                                                #
    # ------------------------------------------------------------------ #

    def solve(
        self,
        assumptions: Iterable[int] = (),
        max_decisions: Optional[int] = None,
    ) -> SolverResult:
        """Run DPLL. Returns a frozen SolverResult.

        ``assumptions``: signed literals temporarily forced (not stored).
        ``max_decisions``: fail-safe budget; exceeding it yields verdict
        "unknown" instead of an unproven sat/unsat claim.
        """
        if max_decisions is not None:
            if isinstance(max_decisions, bool) or not isinstance(max_decisions, int):
                raise SATError("max_decisions must be an int")
            if max_decisions < 0:
                raise SATError("max_decisions must be non-negative")
            if max_decisions > _MAX_DECISIONS_HARD_CAP:
                raise SATError("max_decisions exceeds hard cap")

        for lit in assumptions:
            _check_literal(int(lit))

        clauses = self._clauses
        stats = {"decisions": 0, "propagations": 0}

        if self._trivially_unsat:
            return SolverResult(
                verdict="unsat",
                decisions=0,
                propagations=0,
                n_vars=self.n_vars,
                n_clauses=self.n_clauses,
            )

        # Seed the assignment with assumptions.
        assign: Dict[int, bool] = {}
        for lit in assumptions:
            lit = int(lit)
            v, val = abs(lit), lit > 0
            if v in assign and assign[v] != val:
                return SolverResult(
                    verdict="unsat",
                    n_vars=self.n_vars,
                    n_clauses=self.n_clauses,
                )
            assign[v] = val

        outcome = self._dpll(clauses, assign, stats, max_decisions)

        if outcome == "unknown":
            return SolverResult(
                verdict="unknown",
                decisions=stats["decisions"],
                propagations=stats["propagations"],
                n_vars=self.n_vars,
                n_clauses=self.n_clauses,
            )
        if outcome is None:
            return SolverResult(
                verdict="unsat",
                decisions=stats["decisions"],
                propagations=stats["propagations"],
                n_vars=self.n_vars,
                n_clauses=self.n_clauses,
            )
        assignment = tuple(sorted((v if val else -v) for v, val in outcome.items()))
        return SolverResult(
            verdict="sat",
            assignment=assignment,
            decisions=stats["decisions"],
            propagations=stats["propagations"],
            n_vars=self.n_vars,
            n_clauses=self.n_clauses,
        )

    def _dpll(
        self,
        clauses: List[FrozenSet[int]],
        assign: Dict[int, bool],
        stats: Dict[str, int],
        max_decisions: Optional[int],
    ) -> Optional[object]:
        """Recursive DPLL.

        Returns "unknown" on budget exhaustion, None on conflict, or the
        satisfying assignment dict.
        """
        # --- unit propagation + pure-literal loop -------------------------
        while True:
            unit, conflict = self._propagate(clauses, assign, stats)
            if conflict:
                return None
            if unit is None:
                break
            assign[abs(unit)] = unit > 0

        # --- pure literal elimination -------------------------------------
        pure = self._find_pure_literal(clauses, assign)
        if pure is not None:
            assign[abs(pure)] = pure > 0
            return self._dpll(clauses, assign, stats, max_decisions)

        # --- branch ------------------------------------------------------
        branch = self._pick_branch(clauses, assign)
        if branch is None:
            return assign  # all clauses satisfied
        if max_decisions is not None and stats["decisions"] >= max_decisions:
            return "unknown"
        stats["decisions"] += 1
        for val in (True, False):
            child = dict(assign)
            child[branch] = val
            result = self._dpll(clauses, child, stats, max_decisions)
            if result is not None:
                return result
        return None

    @staticmethod
    def _clause_status(clause: FrozenSet[int], assign: Dict[int, bool]):
        """Return ("sat",), ("unit", lit), ("conflict",), or ("undecided",)."""
        unassigned = []
        for lit in clause:
            v = abs(lit)
            if v not in assign:
                unassigned.append(lit)
            elif (lit > 0) == assign[v]:
                return "sat", None
        if not unassigned:
            return "conflict", None
        if len(unassigned) == 1:
            return "unit", unassigned[0]
        return "undecided", None

    def _propagate(
        self,
        clauses: List[FrozenSet[int]],
        assign: Dict[int, bool],
        stats: Dict[str, int],
    ):
        """One unit-propagation pass. Returns (unit_lit_or_None, conflict)."""
        for clause in clauses:
            status, lit = self._clause_status(clause, assign)
            if status == "conflict":
                return None, True
            if status == "unit":
                stats["propagations"] += 1
                return lit, False
        return None, False

    def _find_pure_literal(
        self, clauses: List[FrozenSet[int]], assign: Dict[int, bool]
    ) -> Optional[int]:
        """A literal is pure if its negation never occurs in an
        unsatisfied, undecided clause."""
        pos: Set[int] = set()
        neg: Set[int] = set()
        for clause in clauses:
            status, _ = self._clause_status(clause, assign)
            if status == "sat":
                continue
            for lit in clause:
                v = abs(lit)
                if v in assign:
                    continue
                if lit > 0:
                    pos.add(v)
                else:
                    neg.add(v)
        pure_pos = pos - neg
        pure_neg = neg - pos
        if pure_pos:
            return min(pure_pos)  # deterministic
        if pure_neg:
            return -min(pure_neg)  # deterministic
        return None

    def _pick_branch(
        self, clauses: List[FrozenSet[int]], assign: Dict[int, bool]
    ) -> Optional[int]:
        """Lowest-numbered unassigned variable occurring in any undecided
        clause. None when every clause is satisfied."""
        best: Optional[int] = None
        for clause in clauses:
            status, _ = self._clause_status(clause, assign)
            if status in ("conflict", "unit"):
                continue
            if status == "sat":
                continue
            for lit in clause:
                v = abs(lit)
                if v not in assign and (best is None or v < best):
                    best = v
        return best


# ---------------------------------------------------------------------- #
# Audit                                                                  #
# ---------------------------------------------------------------------- #

def sat_solver_audit_event(kind: str, result: Optional[SolverResult], seq: int) -> dict:
    """Audit-shaped record for a solver observation.

    ``kind``: "clause-added" (``result`` must be None), "solved-sat",
    "solved-unsat", or "solve-unknown" (``result`` must be a SolverResult
    whose verdict matches the kind).
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown kind {kind!r}")
    _check_seq(seq)
    if kind == "clause-added":
        if result is not None:
            raise TypeError("result must be None for clause-added")
        payload = {"kind": kind}
    else:
        if not isinstance(result, SolverResult):
            raise TypeError("result must be a SolverResult")
        expected = {"solved-sat": "sat", "solved-unsat": "unsat", "solve-unknown": "unknown"}[kind]
        if result.verdict != expected:
            raise ValueError(f"result verdict {result.verdict!r} mismatches kind {kind!r}")
        payload = {"kind": kind, "result": result.as_dict()}
    return {
        "event": "sat-solver",
        "audit_seq": seq,
        "schema": "audit.ndjson/1",
        **payload,
    }


def main() -> None:
    """Self-check: a small SAT instance, a small UNSAT instance, budget."""
    # SAT: (x1 | x2) & (-x1 | x2) & (x1 | -x2)  ->  x1=x2=True
    s = SATSolver()
    s.add_clauses([(1, 2), (-1, 2), (1, -2)])
    r = s.solve()
    assert r.verdict == "sat", r
    assert verify_assignment(r.assignment, [(1, 2), (-1, 2), (1, -2)])
    assert r.model() == {1: True, 2: True}, r.model()

    # UNSAT: the four-clause XOR contradiction.
    u = SATSolver()
    u.add_clauses([(1, 2), (-1, 2), (1, -2), (-1, -2)])
    ru = u.solve()
    assert ru.verdict == "unsat", ru

    # Budget: unsatisfiable-by-exhaustion formula forced to "unknown".
    b = SATSolver()
    b.add_clauses([(1, 2), (-1, 2), (1, -2), (-1, -2)])
    rb = b.solve(max_decisions=0)
    assert rb.verdict == "unknown", rb

    print("sat-solver OK: sat, unsat, unknown-budget, verify")


if __name__ == "__main__":
    main()
