"""Backtracking: 8-puzzle solver via depth-limited DFS (mock).

IS: a tiny depth-limited DFS that finds a move sequence from a start state
    to the goal on the 3x3 sliding puzzle. Only shallow depths are feasible.
IS NOT: a full A*/IDA* solver, a solvability (parity) prover, or an
    optimal-path finder for deep scrambles.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import List, Optional, Tuple

VERSION = "backtrack_31.v1"

GOAL: Tuple[int, ...] = (1, 2, 3, 4, 5, 6, 7, 8, 0)

# Blank-index -> swappable neighbour indices on the 3x3 board.
_NEIGHBOURS = {
    0: (1, 3), 1: (0, 2, 4), 2: (1, 5),
    3: (0, 4, 6), 4: (1, 3, 5, 7), 5: (2, 4, 8),
    6: (3, 7), 7: (4, 6, 8), 8: (5, 7),
}


@dataclass(frozen=True)
class SearchStats:
    expanded: int
    max_depth: int


def successors(state: Tuple[int, ...]) -> List[Tuple[int, ...]]:
    """All states reachable by sliding one tile into the blank."""
    blank = state.index(0)
    out: List[Tuple[int, ...]] = []
    for nb in _NEIGHBOURS[blank]:
        tiles = list(state)
        tiles[blank], tiles[nb] = tiles[nb], tiles[blank]
        out.append(tuple(tiles))
    return out


def solve_dfs(start: Tuple[int, ...], max_depth: int) -> Optional[List[Tuple[int, ...]]]:
    """Depth-limited DFS from ``start`` to :data:`GOAL`.

    Returns the state path (start ... goal) or ``None`` when no path is
    found within ``max_depth`` moves.
    """
    if len(start) != 9 or set(start) != set(range(9)):
        raise ValueError("start must be a permutation of 0..8")
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")

    path: List[Tuple[int, ...]] = [start]
    seen = {start}

    def dfs(depth: int) -> Optional[List[Tuple[int, ...]]]:
        state = path[-1]
        if state == GOAL:
            return list(path)
        if depth == max_depth:
            return None
        for nxt in successors(state):
            if nxt in seen:
                continue
            seen.add(nxt)
            path.append(nxt)
            found = dfs(depth + 1)
            if found is not None:
                return found
            path.pop()
        return None

    return dfs(0)


def is_legal_move(a: Tuple[int, ...], b: Tuple[int, ...]) -> bool:
    """True when ``b`` is one blank-slide away from ``a``."""
    return b in successors(a)


def stdlib_only() -> bool:
    """Parse this file with ``ast``; True only if every import is allowed."""
    allowed = {"__future__", "ast", "dataclasses", "typing"}
    with open(__file__) as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    # start == goal: trivial path
    assert solve_dfs(GOAL, 0) == [GOAL]
    # one move away: (1 2 3 / 4 5 6 / 7 _ 8) -> goal
    one = (1, 2, 3, 4, 5, 6, 7, 0, 8)
    path = solve_dfs(one, 1)
    assert path is not None and len(path) == 2 and path[-1] == GOAL
    assert is_legal_move(path[0], path[1])
    # depth too shallow -> None
    assert solve_dfs(one, 0) is None
    # two moves away: (1 2 3 / 4 5 6 / _ 7 8) -> goal in 2
    two = (1, 2, 3, 4, 5, 6, 0, 7, 8)
    path2 = solve_dfs(two, 2)
    assert path2 is not None and len(path2) == 3 and path2[-1] == GOAL
    assert all(is_legal_move(a, b) for a, b in zip(path2, path2[1:]))
    assert solve_dfs(two, 1) is None
    # bad input
    try:
        solve_dfs((1, 2, 3), 3)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for bad state")
    assert stdlib_only()
    print("backtrack_31 OK")


if __name__ == "__main__":
    main()
