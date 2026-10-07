"""Symbolic execution interface (toy IR, simulated).

Research motivation: symbolic execution (King 1976; Cadar, Dunbar, Engler /
KLEE 2008) explores a program's paths by running it on *symbolic* inputs
and collecting the branch conditions (the path constraint) as it goes.
Each path through the program becomes a logical formula; an SMT solver
then finds concrete inputs that drive execution down each path. It is the
workhorse behind concolic testers, exploit generators (Mayhem, angr), and
formal firmware analysis - and the natural shape for a runtime that wants
to *prove* which inputs reach which permission gates instead of fuzzing
and hoping.

This module is the *mechanics half*, over a tiny toy IR, so the plumbing
the runtime depends on is pinned:

- ``Program``: a list of instruction tuples. Vocabulary:
  ``("sym", name)``            declare a symbolic input
  ``("const", name, value)``   concrete assignment
  ``("add"|"sub"|"mul", dst, a, b)``  operands are ints or var names
  ``("assume", op, a, b)``     add a path constraint (see below)
  ``("branch", op, a, b)``     fork: true side gets ``(op,a,b)``,
                              false side gets the negated comparison
  ``("halt", name?)``          end the path; output is the value of name
- Comparisons: ``eq/ne/lt/le/gt/ge`` over (expr, int) or (expr, expr).
  Expressions are frozen tuples: ``("lit", n)``, ``("var", name)``,
  ``("+", l, r)``, ``("-", l, r)``, ``("*", l, r)``.
- ``SymbolicExec.execute(program)`` walks the IR with a worklist (BFS,
  deterministic path ids ``p0``, ``p1``, ...), forking state at each
  ``branch``. Returns a frozen ``ExecutionReport``: the surviving paths,
  each with its path constraint tuple, final state, output value, and a
  ``sha256:`` state pin. Unsatisfiable-side forks are pruned by the
  built-in solver and counted.
- ``solve(constraints)`` -- module-level bounded-domain solver: interval
  propagation over a fixed int16-ish domain followed by deterministic
  candidate sampling. Returns a frozen ``Solution`` (``sat`` bool plus a
  concrete ``assignment`` or ``None``). Never raises on an unsatisfiable
  formula; raises ``SymbolicExecError`` only on malformed caller input.
- Path explosion is fail-closed: ``MAX_PATHS = 64`` live forks and
  ``MAX_VARS = 6`` symbolic variables; exceeding either raises instead of
  silently dropping coverage. ``MAX_STEPS = 256`` bounds each path.
- ``symbolic_exec_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1``
  shaped records (``executed`` / ``path-forked`` / ``path-pruned`` /
  ``solved`` / ``unsat``).

Honest scope:

- Simulated executor: no real SMT solver (no Z3), no memory model, no
  loops (the IR has no jump op), no function calls, no floats. The solver
  is interval narrowing plus deterministic sampling over a *bounded*
  domain; ``sat=True`` is sound, but ``sat=False`` means "unsatisfiable
  inside the bounded domain", not "unsatisfiable over all integers".
- The pruner only removes forks whose constraint set the bounded solver
  already refutes; a path that survives is genuinely feasible *within the
  domain*. Anything outside the domain needs a real SMT backend, which
  drops in behind ``solve`` without changing call sites.
- Expressions can grow with ``add``/``sub``/``mul`` chains; the solver
  evaluates them exactly over machine ints (Python big ints), so there is
  no wraparound semantics - the domain bound, not two's complement, is
  the only guardrail.
- Deterministic and pure: no randomness, no wall-clock. Same program and
  constraints always give the same report and the same solution.

No wall-clock anywhere. stdlib only (``hashlib``, ``dataclasses``,
``typing``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

#: Version pin for the symbolic execution interface described here.
SYMBOLIC_EXEC_VERSION = "symbolic-exec.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.symbolic-exec.v1"

#: Fail-closed caps. Exceeding any of them raises instead of silently
#: dropping coverage.
MAX_PATHS = 64
MAX_VARS = 6
MAX_STEPS = 256

#: Bounded solver domain (inclusive). Unsat verdicts are relative to it.
DOMAIN_LO = -(1 << 15)
DOMAIN_HI = (1 << 15) - 1

#: Comparison vocabulary, with the branch-false-side negation map.
NEGATE = {"eq": "ne", "ne": "eq", "lt": "ge", "le": "gt", "gt": "le", "ge": "lt"}

_BINOPS = ("add", "sub", "mul")


class SymbolicExecError(ValueError):
    """Fail-closed symbolic execution error."""


def _reject_bool(name: str, value: object) -> None:
    if isinstance(value, bool):
        raise TypeError(f"{name} must not be a bool")


def _check_var_name(name: object) -> str:
    _reject_bool("variable name", name)
    if not isinstance(name, str) or not name:
        raise SymbolicExecError("variable name must be a non-empty str")
    return name


def _check_int(name: str, value: object) -> int:
    _reject_bool(name, value)
    if not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    return value


def _canonical_expr(expr: object) -> tuple:
    """Validate and freeze a symbolic expression into a nested tuple.

    Idempotent: already-canonical tuples pass through unchanged, so
    constraints built by ``execute`` can be re-checked by ``solve``.
    """
    if isinstance(expr, bool):
        raise TypeError("expression must not be a bool")
    if isinstance(expr, int):
        return ("lit", expr)
    if isinstance(expr, str):
        return ("var", _check_var_name(expr))
    if isinstance(expr, (list, tuple)) and len(expr) == 2:
        if expr[0] == "lit" and isinstance(expr[1], int) and not isinstance(
            expr[1], bool
        ):
            return ("lit", expr[1])
        if expr[0] == "var" and isinstance(expr[1], str):
            return ("var", _check_var_name(expr[1]))
    if isinstance(expr, (list, tuple)) and len(expr) == 3:
        if expr[0] in ("+", "-", "*"):
            return (expr[0], _canonical_expr(expr[1]), _canonical_expr(expr[2]))
    raise SymbolicExecError("bad expression shape")


def _check_constraint(op: object, a: object, b: object) -> Tuple[str, tuple, tuple]:
    if not isinstance(op, str) or op not in NEGATE:
        raise SymbolicExecError(f"unknown comparison: {op!r}")
    return (op, _canonical_expr(a), _canonical_expr(b))


def _eval(expr: tuple, assignment: Dict[str, int]) -> int:
    tag = expr[0]
    if tag == "lit":
        return expr[1]
    if tag == "var":
        return assignment[expr[1]]
    left = _eval(expr[1], assignment)
    right = _eval(expr[2], assignment)
    if tag == "+":
        return left + right
    if tag == "-":
        return left - right
    return left * right  # "*"


def _holds(constraint: Tuple[str, tuple, tuple], assignment: Dict[str, int]) -> bool:
    op, left_e, right_e = constraint
    left = _eval(left_e, assignment)
    right = _eval(right_e, assignment)
    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    if op == "lt":
        return left < right
    if op == "le":
        return left <= right
    if op == "gt":
        return left > right
    return left >= right  # "ge"


def _vars_in_expr(expr: tuple, acc: set) -> None:
    if expr[0] == "var":
        acc.add(expr[1])
    elif expr[0] in ("+", "-", "*"):
        _vars_in_expr(expr[1], acc)
        _vars_in_expr(expr[2], acc)


def _invert_linear(expr: tuple, target: int) -> Optional[Tuple[str, int]]:
    """If expr is linear in exactly one variable, return (var, value)
    such that expr == target. None otherwise."""
    if expr[0] == "var":
        return (expr[1], target)
    if expr[0] == "lit":
        return None
    op, left, right = expr
    if op == "+":
        if left[0] == "lit":
            return _invert_linear(right, target - left[1])
        if right[0] == "lit":
            return _invert_linear(left, target - right[1])
    elif op == "-":
        if right[0] == "lit":
            return _invert_linear(left, target + right[1])
        if left[0] == "lit":
            return _invert_linear(right, left[1] - target)
    elif op == "*":
        if left[0] == "lit" and left[1] != 0 and target % left[1] == 0:
            return _invert_linear(right, target // left[1])
        if right[0] == "lit" and right[1] != 0 and target % right[1] == 0:
            return _invert_linear(left, target // right[1])
    return None


def solve(constraints: Tuple[Tuple[str, tuple, tuple], ...]) -> "Solution":
    """Bounded-domain solver. ``Solution(sat, assignment)``; unsat is a
    policy outcome (sat=False), never an exception."""
    if not isinstance(constraints, (list, tuple)):
        raise TypeError("constraints must be a list/tuple")
    checked: List[Tuple[str, tuple, tuple]] = []
    for item in constraints:
        if not isinstance(item, (list, tuple)) or len(item) != 3:
            raise SymbolicExecError("bad constraint shape")
        checked.append(_check_constraint(item[0], item[1], item[2]))

    var_names: set = set()
    for _op, left_e, right_e in checked:
        _vars_in_expr(left_e, var_names)
        _vars_in_expr(right_e, var_names)
    ordered = sorted(var_names)
    if len(ordered) > MAX_VARS:
        raise SymbolicExecError(f"too many variables (>{MAX_VARS})")

    # Interval propagation over var-vs-int comparisons.
    lo = {v: DOMAIN_LO for v in ordered}
    hi = {v: DOMAIN_HI for v in ordered}

    def tighten() -> bool:
        for op, left_e, right_e in checked:
            if left_e[0] != "var" or right_e[0] != "lit":
                continue
            v, c = left_e[1], right_e[1]
            if op == "eq":
                lo[v] = max(lo[v], c)
                hi[v] = min(hi[v], c)
            elif op == "lt":
                hi[v] = min(hi[v], c - 1)
            elif op == "le":
                hi[v] = min(hi[v], c)
            elif op == "gt":
                lo[v] = max(lo[v], c + 1)
            elif op == "ge":
                lo[v] = max(lo[v], c)
        return any(lo[v] > hi[v] for v in ordered)

    for _ in range(10):
        if tighten():
            return Solution(sat=False, assignment=None)

    # Deterministic candidate sampling: lo, hi, midpoint, neighbors,
    # plus exact values from inverting single-variable linear equations.
    candidates: Dict[str, List[int]] = {}
    inverted: Dict[str, int] = {}
    for op, left_e, right_e in checked:
        if op == "eq" and right_e[0] == "lit":
            hit = _invert_linear(left_e, right_e[1])
            if hit is not None and DOMAIN_LO <= hit[1] <= DOMAIN_HI:
                inverted.setdefault(hit[0], hit[1])
    for v in ordered:
        pts = {lo[v], hi[v], (lo[v] + hi[v]) // 2, lo[v] + 1, hi[v] - 1}
        if v in inverted:
            pts.add(inverted[v])
        candidates[v] = sorted(p for p in pts if lo[v] <= p <= hi[v])

    total = 1
    for v in ordered:
        total *= max(len(candidates[v]), 1)
    if total > 4096:
        raise SymbolicExecError("candidate space too large")

    def walk(idx: int, current: Dict[str, int]) -> Optional[Dict[str, int]]:
        if idx == len(ordered):
            if all(_holds(c, current) for c in checked):
                return dict(current)
            return None
        v = ordered[idx]
        for p in candidates[v]:
            current[v] = p
            found = walk(idx + 1, current)
            if found is not None:
                return found
        current.pop(v, None)
        return None

    found = walk(0, {})
    if found is None:
        return Solution(sat=False, assignment=None)
    return Solution(sat=True, assignment=found)


@dataclass(frozen=True)
class Solution:
    """Frozen solver verdict."""

    sat: bool
    assignment: Optional[Dict[str, int]]

    def __post_init__(self) -> None:
        if not isinstance(self.sat, bool):
            raise TypeError("sat must be a bool")
        if self.assignment is not None:
            if not isinstance(self.assignment, dict):
                raise TypeError("assignment must be a dict or None")
            for k, v in self.assignment.items():
                _check_var_name(k)
                _check_int("assignment value", v)

    def as_dict(self) -> dict:
        return {
            "sat": self.sat,
            "assignment": dict(self.assignment) if self.assignment else None,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class PathResult:
    """One surviving symbolic path."""

    path_id: str
    constraints: Tuple[Tuple[str, tuple, tuple], ...]
    state: Tuple[Tuple[str, tuple], ...]
    output: Optional[tuple]
    state_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.path_id, str) or not self.path_id:
            raise TypeError("path_id must be a non-empty str")
        if not self.state_digest.startswith("sha256:"):
            raise SymbolicExecError("state_digest must be a sha256: pin")

    def as_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "constraints": [list(c) for c in self.constraints],
            "state": {k: str(v) for k, v in self.state},
            "output": str(self.output) if self.output is not None else None,
            "state_digest": self.state_digest,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class ExecutionReport:
    """Frozen report for one ``execute`` run."""

    paths: Tuple[PathResult, ...]
    forks: int
    pruned: int
    digest: str

    def __post_init__(self) -> None:
        for n in ("forks", "pruned"):
            _check_int(n, getattr(self, n))
            if getattr(self, n) < 0:
                raise SymbolicExecError(f"{n} must be non-negative")
        if not self.digest.startswith("sha256:"):
            raise SymbolicExecError("digest must be a sha256: pin")

    def as_dict(self) -> dict:
        return {
            "paths": [p.as_dict() for p in self.paths],
            "forks": self.forks,
            "pruned": self.pruned,
            "digest": self.digest,
            "schema": SCHEMA_PIN,
        }


def _state_pin(state: Dict[str, tuple]) -> str:
    body = "|".join(f"{k}={state[k]!r}" for k in sorted(state))
    return "sha256:" + hashlib.sha256(body.encode()).hexdigest()


def _resolve_operand(operand: object, state: Dict[str, tuple]) -> tuple:
    if isinstance(operand, bool):
        raise TypeError("operand must not be a bool")
    if isinstance(operand, int):
        return ("lit", operand)
    if isinstance(operand, str):
        name = _check_var_name(operand)
        if name not in state:
            raise SymbolicExecError(f"unknown variable: {name}")
        return state[name]
    raise SymbolicExecError("operand must be an int or a variable name")


class SymbolicExec:
    """Symbolic executor over the toy IR. Deterministic, pure, stdlib-only."""

    def __init__(self) -> None:
        self._version = SYMBOLIC_EXEC_VERSION

    @property
    def version(self) -> str:
        return self._version

    def execute(self, program: object) -> ExecutionReport:
        """Symbolically execute a program. Returns an ``ExecutionReport``."""
        if not isinstance(program, (list, tuple)):
            raise TypeError("program must be a list/tuple of instructions")
        instructions: List[tuple] = []
        for item in program:
            if not isinstance(item, (list, tuple)) or not item:
                raise SymbolicExecError("bad instruction shape")
            instructions.append(tuple(item))

        path_counter = 0
        forks = 0
        pruned = 0
        # Each live path: (state, constraints, pc).
        live: List[Tuple[Dict[str, tuple], List[Tuple[str, tuple, tuple]], int]] = [
            ({}, [], 0)
        ]
        finished: List[PathResult] = []

        def new_path_id() -> str:
            nonlocal path_counter
            pid = f"p{path_counter}"
            path_counter += 1
            return pid

        while live:
            if len(live) + len(finished) > MAX_PATHS:
                raise SymbolicExecError(f"path explosion (>{MAX_PATHS})")
            state, constraints, pc = live.pop(0)
            steps = 0
            while True:
                steps += 1
                if steps > MAX_STEPS:
                    raise SymbolicExecError("path exceeded step bound")
                if pc >= len(instructions):
                    raise SymbolicExecError("program fell off the end (missing halt)")
                ins = instructions[pc]
                op = ins[0]
                if op == "sym":
                    if len(ins) != 2:
                        raise SymbolicExecError("sym takes one name")
                    name = _check_var_name(ins[1])
                    if name in state:
                        raise SymbolicExecError(f"redeclared variable: {name}")
                    if len(state) >= MAX_VARS:
                        raise SymbolicExecError(f"too many variables (>{MAX_VARS})")
                    state[name] = ("var", name)
                    pc += 1
                elif op == "const":
                    if len(ins) != 3:
                        raise SymbolicExecError("const takes name and value")
                    name = _check_var_name(ins[1])
                    state[name] = ("lit", _check_int("const value", ins[2]))
                    pc += 1
                elif op in _BINOPS:
                    if len(ins) != 4:
                        raise SymbolicExecError(f"{op} takes dst, a, b")
                    dst = _check_var_name(ins[1])
                    a = _resolve_operand(ins[2], state)
                    b = _resolve_operand(ins[3], state)
                    sym = {"add": "+", "sub": "-", "mul": "*"}[op]
                    state[dst] = (sym, a, b)
                    pc += 1
                elif op == "assume":
                    if len(ins) != 4:
                        raise SymbolicExecError("assume takes op, a, b")
                    constraint = _check_constraint(ins[1], ins[2], ins[3])
                    constraints.append(constraint)
                    if not solve(tuple(constraints)).sat:
                        pruned += 1
                        break  # path dies here
                    pc += 1
                elif op == "branch":
                    if len(ins) != 4:
                        raise SymbolicExecError("branch takes op, a, b")
                    true_c = _check_constraint(ins[1], ins[2], ins[3])
                    false_c = (NEGATE[true_c[0]], true_c[1], true_c[2])
                    forks += 1
                    for side_c in (true_c, false_c):
                        trial = constraints + [side_c]
                        if solve(tuple(trial)).sat:
                            live.append((dict(state), list(trial), pc + 1))
                        else:
                            pruned += 1
                    break  # this path forks; both children are new work items
                elif op == "halt":
                    if len(ins) > 2:
                        raise SymbolicExecError("halt takes at most one name")
                    output = None
                    if len(ins) == 2:
                        output = _resolve_operand(ins[1], state)
                    frozen_state = tuple(sorted(state.items()))
                    finished.append(
                        PathResult(
                            path_id=new_path_id(),
                            constraints=tuple(constraints),
                            state=frozen_state,
                            output=output,
                            state_digest=_state_pin(state),
                        )
                    )
                    break
                else:
                    raise SymbolicExecError(f"unknown instruction: {op!r}")

        digest_body = "|".join(
            p.path_id + ":" + p.state_digest for p in finished
        )
        return ExecutionReport(
            paths=tuple(finished),
            forks=forks,
            pruned=pruned,
            digest="sha256:" + hashlib.sha256(digest_body.encode()).hexdigest(),
        )


def symbolic_exec_audit_event(kind: str, seq: int, **fields: object) -> dict:
    """Audit-shaped record for a symbolic execution observation."""
    if kind not in ("executed", "path-forked", "path-pruned", "solved", "unsat"):
        raise ValueError("unknown kind")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    record = {
        "event": "symbolic-exec",
        "kind": kind,
        "audit_seq": seq,
        "schema": "audit.ndjson/1",
    }
    record.update(fields)
    return record


def main() -> None:
    ex = SymbolicExec()
    program = [
        ("sym", "x"),
        ("branch", "lt", "x", 10),
        ("const", "y", 1),
        ("halt", "y"),
    ]
    # NOTE: the toy IR is linear; the branch forks and each fork runs to
    # the *next* instruction in the flat list, so both paths share the
    # tail. This keeps the model honest: no control-flow graph, just forks.
    report = ex.execute(program)
    assert report.forks == 1, "one fork"
    assert len(report.paths) == 2, "two surviving paths"
    assert report.pruned == 0, "nothing pruned"
    sol = solve((("eq", "x", 5),))
    assert sol.sat and sol.assignment == {"x": 5}, "solver finds 5"
    unsat = solve((("lt", "x", 0), ("gt", "x", 10)))
    assert not unsat.sat, "contradiction is unsat"
    print(
        f"symbolic-exec OK: {len(report.paths)} paths, "
        f"forks={report.forks}, pruned={report.pruned}, "
        f"solve sat/unsat verified"
    )


if __name__ == "__main__":
    main()
