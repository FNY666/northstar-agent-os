"""DX-25: Dependency graphs (mock), Simulated.

Directed import graph over declared packages. `dependencies(pkg)`
returns direct deps, `dependents(pkg)` reverse deps, `transitive(pkg)`
the full closure, and `topo_sort()` a deterministic ordering via
Kahn's algorithm; cycles raise.

What this IS: explicit graph queries over a declared edge set.
What this IS NOT: not parsed from real imports.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Set

#: Module version.
DX25_DEPS_VERSION = "dx-deps.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-deps.v1"


class DepGraphError(Exception):
    """Fail-closed."""


class DepGraph:
    """Directed package dependency graph."""

    def __init__(self) -> None:
        self._edges: Dict[str, Set[str]] = {}

    def _require(self, pkg: str) -> None:
        if pkg not in self._edges:
            raise DepGraphError(f"unknown package '{pkg}'")

    def add_edge(self, src: str, dst: str) -> None:
        if not src or not dst:
            raise DepGraphError("src and dst required")
        if src == dst:
            raise DepGraphError("self-dependency not allowed")
        self._edges.setdefault(src, set()).add(dst)
        self._edges.setdefault(dst, set())

    def dependencies(self, pkg: str) -> List[str]:
        self._require(pkg)
        return sorted(self._edges[pkg])

    def dependents(self, pkg: str) -> List[str]:
        self._require(pkg)
        return sorted(s for s, ds in self._edges.items() if pkg in ds)

    def transitive(self, pkg: str) -> List[str]:
        self._require(pkg)
        seen: Set[str] = set()
        stack = sorted(self._edges[pkg])
        while stack:
            cur = stack.pop(0)
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(sorted(self._edges[cur] - seen))
        return sorted(seen)

    def topo_sort(self) -> List[str]:
        indeg = {p: 0 for p in self._edges}
        for ds in self._edges.values():
            for d in ds:
                indeg[d] += 1
        queue = sorted(p for p, n in indeg.items() if n == 0)
        order: List[str] = []
        while queue:
            cur = queue.pop(0)
            order.append(cur)
            for d in sorted(self._edges[cur]):
                indeg[d] -= 1
                if indeg[d] == 0:
                    queue.append(d)
            queue.sort()
        if len(order) != len(self._edges):
            raise DepGraphError("dependency cycle detected")
        return order

    @property
    def packages(self) -> List[str]:
        return sorted(self._edges)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    g = DepGraph()
    g.add_edge("app", "lib")
    g.add_edge("app", "util")
    g.add_edge("lib", "util")
    assert g.dependencies("app") == ["lib", "util"]
    assert g.dependents("util") == ["app", "lib"]
    assert g.transitive("app") == ["lib", "util"]
    assert g.topo_sort().index("app") < g.topo_sort().index("lib")
    cyc = DepGraph()
    cyc.add_edge("a", "b")
    cyc.add_edge("b", "a")
    try:
        cyc.topo_sort()
        raise AssertionError("should raise")
    except DepGraphError:
        pass
    try:
        g.add_edge("x", "x")
        raise AssertionError("should raise")
    except DepGraphError:
        pass
    try:
        g.dependencies("nope")
        raise AssertionError("should raise")
    except DepGraphError:
        pass
    assert stdlib_only()
    print("dx_25 OK: deps, dependents, transitive, topo, cycle rejected")


if __name__ == "__main__":
    main()
