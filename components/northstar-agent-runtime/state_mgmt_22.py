"""State 22: state reconciliation (mock), Simulated.

Reconcile two divergent replicas into a converged pair:
- plan(a, b): compute the op list (pull newer / push newer) needed to
  converge, without applying anything
- apply(plan): execute the ops against both replicas
- reconcile(a, b): plan + apply; returns the op list

Entries are (value, version) like state_mgmt_20; ties on version with
different values are reported as conflicts and left unresolved (the
caller picks a Conflict resolution from state_mgmt_23).

Mock: in-process dicts.

Fail-closed: malformed entries, version ties with differing values
are surfaced as conflicts (not silently dropped).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Tuple


MODULE_VERSION = "state-mgmt-22.v1"
SCHEMA_PIN = "northstar.state-mgmt-22.v1"


class ReconcileError(Exception):
    pass


Entry = Tuple[str, int]


def _check(key: str, entry: Entry) -> None:
    if not isinstance(key, str) or not key:
        raise ReconcileError("key must be non-empty str")
    if (not isinstance(entry, tuple) or len(entry) != 2
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], int) or isinstance(entry[1], bool)
            or entry[1] < 0):
        raise ReconcileError(f"malformed entry for {key!r}")


@dataclass(frozen=True)
class Op:
    action: str          # "a_pull" | "b_pull"
    key: str
    value: str
    version: int

    def __post_init__(self):
        if self.action not in ("a_pull", "b_pull"):
            raise ReconcileError(f"bad action {self.action!r}")


@dataclass(frozen=True)
class Conflict:
    key: str
    a_value: str
    b_value: str
    version: int


@dataclass(frozen=True)
class Plan:
    ops: Tuple[Op, ...]
    conflicts: Tuple[Conflict, ...]


class Store:
    def __init__(self, data: Dict[str, Entry] | None = None) -> None:
        self.data: Dict[str, Entry] = {}
        for k, e in (data or {}).items():
            _check(k, e)
            self.data[k] = e


def plan(a: Store, b: Store) -> Plan:
    ops: List[Op] = []
    conflicts: List[Conflict] = []
    for key in sorted(set(a.data) | set(b.data)):
        ea = a.data.get(key)
        eb = b.data.get(key)
        if ea is None:
            assert eb is not None
            ops.append(Op("a_pull", key, eb[0], eb[1]))
        elif eb is None:
            ops.append(Op("b_pull", key, ea[0], ea[1]))
        elif ea[1] > eb[1]:
            ops.append(Op("b_pull", key, ea[0], ea[1]))
        elif eb[1] > ea[1]:
            ops.append(Op("a_pull", key, eb[0], eb[1]))
        elif ea[0] != eb[0]:
            conflicts.append(Conflict(key, ea[0], eb[0], ea[1]))
    return Plan(tuple(ops), tuple(conflicts))


def apply(plan_: Plan, a: Store, b: Store) -> None:
    for op in plan_.ops:
        if op.action == "a_pull":
            a.data[op.key] = (op.value, op.version)
        else:
            b.data[op.key] = (op.value, op.version)


def reconcile(a: Store, b: Store) -> Plan:
    p = plan(a, b)
    apply(p, a, b)
    return p


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for x in node.names:
                if x.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    a = Store({"k": ("v1", 1), "only_a": ("x", 1)})
    b = Store({"k": ("v2", 2), "only_b": ("y", 3)})
    p = plan(a, b)
    assert len(p.ops) == 3 and not p.conflicts
    # Plan is pure: stores untouched.
    assert "only_b" not in a.data
    reconcile(a, b)
    assert a.data == b.data
    # Version tie, different values -> conflict, not silently merged.
    c, d = Store({"k": ("vA", 5)}), Store({"k": ("vB", 5)})
    p2 = reconcile(c, d)
    assert len(p2.conflicts) == 1 and p2.conflicts[0].key == "k"
    assert c.data["k"] == ("vA", 5)  # untouched
    try:
        Store({"k": ("v", -1)})
        raise AssertionError("should raise")
    except ReconcileError:
        pass
    assert stdlib_only()
    print("state_mgmt_22 OK: plan/apply split, conflicts surfaced")


if __name__ == "__main__":
    main()
