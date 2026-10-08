"""Backtracking: Kakuro-style sum constraints (mock, simplified).

IS: fills cells with digits 1-9 so that each given run (cell group) sums
    to its target with no repeated digit inside a run, via backtracking
    with sum-range pruning.
IS NOT: a full Kakuro puzzle parser/solver; it does not model clue-cell
    geometry, only the hand-supplied run list.
"""

from __future__ import annotations

import ast
from typing import List, Tuple

VERSION = "backtrack_34.v1"

Cell = Tuple[int, int]
Run = Tuple[List[Cell], int]


def solve_kakuro(runs: List[Run]) -> List[dict]:
    """Return all digit assignments satisfying every run's sum/uniqueness."""
    for cells, target in runs:
        if len(set(cells)) != len(cells):
            raise ValueError("duplicate cell inside a run")
        if len(cells) > 9:
            return []
        if not 1 <= target <= 9 * len(cells):
            return []

    cells: List[Cell] = []
    for run_cells, _ in runs:
        for cell in run_cells:
            if cell not in cells:
                cells.append(cell)
    run_cells = [list(rc) for rc, _ in runs]
    targets = [t for _, t in runs]
    cell_runs: dict = {cell: [] for cell in cells}
    for i, rc in enumerate(run_cells):
        for cell in rc:
            cell_runs[cell].append(i)

    assign: dict = {}
    solutions: List[dict] = []

    def run_ok(i: int) -> bool:
        rc, target = run_cells[i], targets[i]
        total = 0
        unassigned = 0
        used = set()
        for cell in rc:
            if cell in assign:
                total += assign[cell]
                used.add(assign[cell])
            else:
                unassigned += 1
        if total > target:
            return False
        avail = [d for d in range(1, 10) if d not in used]
        if len(avail) < unassigned:
            return False
        lo = sum(avail[:unassigned])
        hi = sum(avail[-unassigned:]) if unassigned else 0
        return total + lo <= target <= total + hi

    def bt(i: int) -> None:
        if i == len(cells):
            if all(run_ok(j) for j in range(len(run_cells))):
                solutions.append(dict(assign))
            return
        cell = cells[i]
        for d in range(1, 10):
            if any(assign.get(other) == d
                   for ri in cell_runs[cell]
                   for other in run_cells[ri] if other != cell):
                continue
            assign[cell] = d
            if all(run_ok(ri) for ri in cell_runs[cell]):
                bt(i + 1)
            del assign[cell]

    bt(0)
    return solutions


def stdlib_only() -> bool:
    """Parse this file with ast; True only if every import is allowed."""
    allowed = {"__future__", "ast", "typing"}
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


def _check(sol: dict, runs: List[Run]) -> bool:
    for rc, target in runs:
        vals = [sol[c] for c in rc]
        if not all(1 <= v <= 9 for v in vals):
            return False
        if len(set(vals)) != len(vals) or sum(vals) != target:
            return False
    return True


def main() -> None:
    # single 2-cell run summing to 3 -> {1,2} in both orders
    runs = [([(0, 0), (0, 1)], 3)]
    sols = solve_kakuro(runs)
    assert len(sols) == 2, sols
    assert all(_check(s, runs) for s in sols)
    # two crossing runs share (0,0): forces a unique solution
    runs2 = [([(0, 0), (0, 1)], 3), ([(0, 0), (1, 0)], 4)]
    sols2 = solve_kakuro(runs2)
    assert len(sols2) == 1, sols2
    assert sols2[0] == {(0, 0): 1, (0, 1): 2, (1, 0): 3}
    # impossible: one cell cannot sum to 10
    assert solve_kakuro([([(0, 0)], 10)]) == []
    # impossible: 2 cells min sum is 3, target 2
    assert solve_kakuro([([(0, 0), (0, 1)], 2)]) == []
    # duplicate cell in a run -> ValueError
    try:
        solve_kakuro([([(0, 0), (0, 0)], 5)])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for duplicate cell")
    assert stdlib_only()
    print("backtrack_34 OK")


if __name__ == "__main__":
    main()
