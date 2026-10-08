"""Backtracking: Hamiltonian path in a small graph.

IS: find one path that visits every vertex of an undirected graph exactly
once (a Hamiltonian path). Vertices are arbitrary hashables; the graph is
given as an adjacency map. With no fixed start, every vertex is tried as
a start; with a fixed start only that start is tried.

IS NOT: the Hamiltonian *cycle* problem (no return-to-start edge is
required), TSP (no weights), or a proof of non-existence - returning
None means the backtracking search exhausted the space, which is
exponential in the worst case.

Self-test harness: run ``python backtrack_19.py``.
"""

from dataclasses import dataclass
from typing import Dict, Hashable, List, Optional, Set, Tuple

VERSION = "backtrack_19.v1"

_ALLOWED_IMPORTS = frozenset({"typing", "dataclasses", "itertools", "ast"})


def stdlib_only() -> bool:
    """Parse this file with ``ast``; True only if every import comes from the
    allowed stdlib set."""
    import ast

    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=__file__)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0:
                return False
            if (node.module or "").split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


Adjacency = Dict[Hashable, List[Hashable]]


@dataclass(frozen=True)
class HamiltonianResult:
    """Outcome of the search: the path, or None when none exists."""
    path: Optional[Tuple[Hashable, ...]]

    @property
    def found(self) -> bool:
        return self.path is not None


def hamiltonian_path(adj: Adjacency, start: Optional[Hashable] = None) -> HamiltonianResult:
    """Search for a Hamiltonian path; optionally pinned to ``start``."""
    n = len(adj)
    if n == 0:
        return HamiltonianResult(path=())
    if n == 1:
        return HamiltonianResult(path=(next(iter(adj)),))

    def dfs(cur: Hashable, visited: Set[Hashable],
            path: List[Hashable]) -> Optional[Tuple[Hashable, ...]]:
        if len(path) == n:
            return tuple(path)
        for nxt in adj[cur]:
            if nxt not in visited:
                visited.add(nxt)
                path.append(nxt)
                found = dfs(nxt, visited, path)
                if found is not None:
                    return found
                path.pop()
                visited.discard(nxt)
        return None

    starts = [start] if start is not None else list(adj)
    for s in starts:
        if s not in adj:
            continue
        hit = dfs(s, {s}, [s])
        if hit is not None:
            return HamiltonianResult(path=hit)
    return HamiltonianResult(path=None)


def _valid_path(adj: Adjacency, path: Optional[Tuple[Hashable, ...]]) -> bool:
    if path is None:
        return False
    if sorted(path) != sorted(adj):  # visits every vertex exactly once
        return False
    return all(b in adj[a] for a, b in zip(path, path[1:]))


def main() -> None:
    # Linear graph a-b-c-d: a Hamiltonian path must exist.
    line = {"a": ["b"], "b": ["a", "c"], "c": ["b", "d"], "d": ["c"]}
    r = hamiltonian_path(line)
    assert r.found and _valid_path(line, r.path), r
    # Pinned start must be honored.
    r = hamiltonian_path(line, start="a")
    assert r.found and r.path is not None and r.path[0] == "a"
    # Complete graph K4: a path exists from any start.
    k4 = {i: [j for j in range(4) if j != i] for i in range(4)}
    r = hamiltonian_path(k4)
    assert r.found and _valid_path(k4, r.path), r
    # Disconnected graph: no Hamiltonian path.
    disc = {"a": ["b"], "b": ["a"], "c": [], "d": []}
    assert hamiltonian_path(disc).found is False
    # Empty graph: the vacuous path.
    assert hamiltonian_path({}).found is True
    assert stdlib_only() is True
    print("backtrack_19 OK")


if __name__ == "__main__":
    main()
