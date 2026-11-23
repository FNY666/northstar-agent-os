"""Binary decision diagrams: reduced ordered BDDs for boolean functions.

A ``BDD`` is a canonical representation of a boolean function over a fixed
variable ordering (Bryant 1986). Reduced ordered BDDs are *canonical*:
logically equivalent functions built with the same ordering share one node
identity, so equivalence is pointer comparison.

* ``var(name)`` — introduce (or reuse) a boolean variable; variables are
  ordered by first creation.
* ``and_op(a, b)`` / ``or_op(a, b)`` / ``not_op(a)`` — structural ops via the
  ``apply`` algorithm with memoization.
* ``sat_count(node)`` — exact number of satisfying assignments (the #SAT
  count for the function over all declared variables).
* ``node_count(node)`` / ``var_count()`` — structural views.
* ``evaluate(node, assignment)`` — evaluate under a concrete assignment.

House style: no wall-clock, fail-closed, stdlib-only, deterministic, frozen
records, version/schema pins, ``main()`` self-check.

Honest scope: this is the *interface + canonicalization machinery*, not a
solver backend — BDDs can still blow up exponentially in the variable
ordering (s-multiplexer and friends), and no variable-reordering heuristic
is implemented; a bad creation order produces a big BDD. Node ids pin the
*structure*, not the truth of the modelled formula. Nodes are bound to the
``BDD`` instance that built them; mixing nodes across instances is refused.

Version pin: bdd-interface.v1
Schema pin: northstar.bdd-interface.v1
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass

BDD_VERSION = "bdd-interface.v1"
SCHEMA_PIN = "northstar.bdd-interface.v1"

#: Structural ids reserved for the two terminal nodes.
FALSE_ID = 0
TRUE_ID = 1

#: Guardrail on how many variables one BDD instance may hold.
MAX_VARS = 4096


class BDDError(Exception):
    """Structural misuse: bad names, foreign nodes, bad assignments."""


def _require_var_name(name) -> str:
    if isinstance(name, bool) or not isinstance(name, str):
        raise TypeError(f"variable name must be a str, got {type(name).__name__}")
    if not name:
        raise ValueError("variable name must be non-empty")
    return name


def _require_non_negative_int(name: str, value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


@dataclass(frozen=True)
class NodeInfo:
    """Frozen structural view of one BDD node (never the manager internals)."""

    node_id: int
    var: str | None  # None for terminal nodes
    var_index: int | None
    low: int | None  # None for terminal nodes
    high: int | None
    is_terminal: bool

    def as_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "var": self.var,
            "var_index": self.var_index,
            "low": self.low,
            "high": self.high,
            "is_terminal": self.is_terminal,
            "schema": SCHEMA_PIN,
        }


class BDD:
    """Reduced ordered BDD manager over one fixed variable ordering."""

    def __init__(self) -> None:
        # Instance token: nodes from another BDD are foreign and refused.
        self._token = object()
        # (var_index, low_id, high_id) -> node id, the unique table.
        self._unique: dict[tuple[int, int, int], int] = {}
        # node id -> (var_index | None, low | None, high | None).
        self._nodes: dict[int, tuple[int | None, int | None, int | None]] = {
            FALSE_ID: (None, None, None),
            TRUE_ID: (None, None, None),
        }
        self._next_id = 2
        self._var_names: list[str] = []  # var_index -> name
        self._var_index: dict[str, int] = {}  # name -> var_index
        self._apply_cache: dict[tuple[str, int, int], int] = {}

    # -- variables ---------------------------------------------------------
    def var(self, name: str) -> "BDDRef":
        """Introduce (or reuse) variable ``name``; ordering is creation order."""
        name = _require_var_name(name)
        if name in self._var_index:
            index = self._var_index[name]
        else:
            if len(self._var_names) >= MAX_VARS:
                raise BDDError("variable limit reached")
            index = len(self._var_names)
            self._var_names.append(name)
            self._var_index[name] = index
        node_id = self._make_node(index, FALSE_ID, TRUE_ID)
        return BDDRef(self._token, node_id)

    def var_count(self) -> int:
        """How many variables are declared in this instance."""
        return len(self._var_names)

    def var_names(self) -> tuple[str, ...]:
        """Declared variable names in ordering."""
        return tuple(self._var_names)

    # -- structural ops ----------------------------------------------------
    def _make_node(self, var_index: int, low: int, high: int) -> int:
        if low == high:
            return low  # reduction rule: skip redundant tests
        key = (var_index, low, high)
        node_id = self._unique.get(key)
        if node_id is None:
            node_id = self._next_id
            self._next_id += 1
            self._unique[key] = node_id
            self._nodes[node_id] = (var_index, low, high)
        return node_id

    def _ref_id(self, ref: "BDDRef") -> int:
        if not isinstance(ref, BDDRef):
            raise TypeError("expected a BDDRef from this BDD instance")
        if ref._token is not self._token:
            raise BDDError("node belongs to a different BDD instance")
        return ref._node_id

    def not_op(self, a: "BDDRef") -> "BDDRef":
        """Negate a boolean function."""
        node = self._ref_id(a)
        return BDDRef(self._token, self._apply("not", node, node))

    def and_op(self, a: "BDDRef", b: "BDDRef") -> "BDDRef":
        """Conjunction of two boolean functions."""
        return BDDRef(self._token, self._apply("and", self._ref_id(a), self._ref_id(b)))

    def or_op(self, a: "BDDRef", b: "BDDRef") -> "BDDRef":
        """Disjunction of two boolean functions."""
        return BDDRef(self._token, self._apply("or", self._ref_id(a), self._ref_id(b)))

    def xor_op(self, a: "BDDRef", b: "BDDRef") -> "BDDRef":
        """Exclusive disjunction."""
        return BDDRef(self._token, self._apply("xor", self._ref_id(a), self._ref_id(b)))

    def implies_op(self, a: "BDDRef", b: "BDDRef") -> "BDDRef":
        """Logical implication (a -> b) = (not a) or b."""
        return BDDRef(self._token, self._apply("implies", self._ref_id(a), self._ref_id(b)))

    def _apply(self, op: str, u1: int, u2: int) -> int:
        key = (op, u1, u2)
        cached = self._apply_cache.get(key)
        if cached is not None:
            return cached
        result = self._apply_compute(op, u1, u2)
        self._apply_cache[key] = result
        return result

    def _apply_compute(self, op: str, u1: int, u2: int) -> int:
        # Terminal cases.
        if op == "not":
            return self._not_terminal(u1)
        if op == "and":
            if u1 == FALSE_ID or u2 == FALSE_ID:
                return FALSE_ID
            if u1 == TRUE_ID:
                return u2
            if u2 == TRUE_ID:
                return u1
        elif op == "or":
            if u1 == TRUE_ID or u2 == TRUE_ID:
                return TRUE_ID
            if u1 == FALSE_ID:
                return u2
            if u2 == FALSE_ID:
                return u1
        elif op == "xor":
            if u1 == FALSE_ID:
                return u2
            if u2 == FALSE_ID:
                return u1
            if u1 == TRUE_ID:
                return self._apply("not", u2, u2)
            if u2 == TRUE_ID:
                return self._apply("not", u1, u1)
        elif op == "implies":
            if u1 == FALSE_ID or u2 == TRUE_ID:
                return TRUE_ID
            if u1 == TRUE_ID:
                return u2
            if u2 == FALSE_ID:
                return self._apply("not", u1, u1)

        if op != "not" and u1 == u2:
            if op in ("and", "or"):
                return u1
            if op == "xor":
                return FALSE_ID
            if op == "implies":
                return TRUE_ID

        v1, _, _ = self._nodes[u1]
        v2, _, _ = self._nodes[u2]
        top = min(i for i in (v1, v2) if i is not None)
        low1, high1 = self._cofactor(u1, top)
        low2, high2 = self._cofactor(u2, top) if op != "not" else (low1, high1)
        if op == "not":
            low, high = self._apply(op, low1, low1), self._apply(op, high1, high1)
        else:
            low, high = self._apply(op, low1, low2), self._apply(op, high1, high2)
        return self._make_node(top, low, high)

    def _not_terminal(self, node: int) -> int:
        if node == TRUE_ID:
            return FALSE_ID
        if node == FALSE_ID:
            return TRUE_ID
        var, low, high = self._nodes[node]
        return self._make_node(
            var,
            self._apply("not", low, low),
            self._apply("not", high, high),
        )

    def _cofactor(self, node: int, var_index: int) -> tuple[int, int]:
        var, low, high = self._nodes[node]
        if var == var_index:
            return low, high
        return node, node

    # -- views -------------------------------------------------------------
    def is_true(self, ref: "BDDRef") -> bool:
        """True iff the function is the constant True."""
        return self._ref_id(ref) == TRUE_ID

    def is_false(self, ref: "BDDRef") -> bool:
        """True iff the function is the constant False."""
        return self._ref_id(ref) == FALSE_ID

    def node_info(self, ref: "BDDRef") -> NodeInfo:
        """Frozen structural view of a node."""
        node = self._ref_id(ref)
        var_index, low, high = self._nodes[node]
        return NodeInfo(
            node_id=node,
            var=self._var_names[var_index] if var_index is not None else None,
            var_index=var_index,
            low=low,
            high=high,
            is_terminal=node in (FALSE_ID, TRUE_ID),
        )

    def node_count(self, ref: "BDDRef") -> int:
        """Number of distinct nodes reachable from ``ref`` (shared counted once)."""
        root = self._ref_id(ref)
        seen: set[int] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            _, low, high = self._nodes[node]
            if low is not None:
                stack.extend((low, high))
        return len(seen)

    def equivalent(self, a: "BDDRef", b: "BDDRef") -> bool:
        """Logical equivalence = shared node identity (canonicity)."""
        return self._ref_id(a) == self._ref_id(b)

    def sat_count(self, ref: "BDDRef") -> int:
        """Exact number of satisfying assignments over all declared variables."""
        root = self._ref_id(ref)
        memo: dict[int, int] = {}

        def count(node: int) -> int:
            if node in memo:
                return memo[node]
            if node == FALSE_ID:
                result = 0
            elif node == TRUE_ID:
                result = 1
            else:
                var_index, low, high = self._nodes[node]
                result = self._count_children(node, low, high, count)
            memo[node] = result
            return result

        total = count(root)
        if root == TRUE_ID:
            return 1 << len(self._var_names)
        if root == FALSE_ID:
            return 0
        # Skipped variables above the root each double the count.
        top = self._nodes[root][0]
        return total * (1 << top)

    def _count_children(self, node: int, low: int, high: int, count) -> int:
        var_index = self._nodes[node][0]
        low_span = self._level_span_to(var_index, low)
        high_span = self._level_span_to(var_index, high)
        return (count(low) << low_span) + (count(high) << high_span)

    def _level_span_to(self, parent_var: int, child: int) -> int:
        child_var = self._nodes[child][0]
        if child_var is None:
            # Terminal: all remaining levels (parent_var+1 .. n-1) are skipped.
            return len(self._var_names) - parent_var - 1
        return child_var - parent_var - 1

    def evaluate(self, ref: "BDDRef", assignment: dict) -> bool:
        """Evaluate the function under ``assignment`` (name -> bool)."""
        if not isinstance(assignment, dict):
            raise TypeError("assignment must be a dict")
        node = self._ref_id(ref)
        while node not in (FALSE_ID, TRUE_ID):
            var_index, low, high = self._nodes[node]
            name = self._var_names[var_index]
            if name not in assignment:
                raise BDDError(f"assignment missing variable {name!r}")
            value = assignment[name]
            if isinstance(value, bool) is False:
                raise TypeError(f"assignment[{name!r}] must be a bool")
            node = high if value else low
        return node == TRUE_ID

    def all_sat(self, ref: "BDDRef", limit: int = 1024) -> list[dict[str, bool]]:
        """Enumerate satisfying assignments (bounded by ``limit``)."""
        _require_non_negative_int("limit", limit)
        if limit == 0:
            raise ValueError("limit must be positive")
        root = self._ref_id(ref)
        results: list[dict[str, bool]] = []

        def walk(node: int, path: list[tuple[str, bool]]) -> None:
            if len(results) >= limit:
                return
            if node == FALSE_ID:
                return
            if node == TRUE_ID:
                base = dict(path)
                # Fill unassigned (skipped) variables with every combination.
                missing = [n for n in self._var_names if n not in base]
                for combo in itertools.product((False, True), repeat=len(missing)):
                    if len(results) >= limit:
                        return
                    results.append({**base, **dict(zip(missing, combo))})
                return
            var_index, low, high = self._nodes[node]
            name = self._var_names[var_index]
            walk(low, path + [(name, False)])
            walk(high, path + [(name, True)])

        walk(root, [])
        return results


@dataclass(frozen=True)
class BDDRef:
    """Opaque handle to a BDD node. Only its owning ``BDD`` may use it."""

    _token: object
    _node_id: int


def bdd_audit_event(bdd: BDD, ref: BDDRef, outcome: str, seq: int) -> dict:
    """Audit-shaped record for a BDD observation."""
    if not isinstance(bdd, BDD):
        raise TypeError("bdd must be a BDD")
    if not isinstance(ref, BDDRef):
        raise TypeError("ref must be a BDDRef")
    if outcome not in ("built", "queried", "counted", "evaluated", "rejected"):
        raise ValueError("unknown outcome")
    _require_non_negative_int("seq", seq)
    info = bdd.node_info(ref)
    return {
        "event": "bdd-interface",
        "outcome": outcome,
        "audit_seq": seq,
        "node": info.as_dict(),
        "schema": "audit.ndjson/1",
    }


def main() -> None:
    bdd = BDD()
    x = bdd.var("x")
    y = bdd.var("y")
    f = bdd.and_op(x, y)  # x & y
    g = bdd.or_op(x, y)  # x | y
    assert bdd.sat_count(f) == 1, bdd.sat_count(f)
    assert bdd.sat_count(g) == 3, bdd.sat_count(g)
    assert bdd.equivalent(f, bdd.and_op(y, x))  # canonical: same node
    assert bdd.evaluate(f, {"x": True, "y": True})
    assert not bdd.evaluate(f, {"x": True, "y": False})
    assert bdd.is_false(bdd.and_op(x, bdd.not_op(x)))
    assert bdd.is_true(bdd.or_op(x, bdd.not_op(x)))
    print(f"bdd-interface OK: sat_count(x&y)=1 sat_count(x|y)=3 node_count={bdd.node_count(g)}")


if __name__ == "__main__":
    main()
