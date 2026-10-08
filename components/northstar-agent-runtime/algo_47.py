"""Matrix chain multiplication order via dynamic programming.

For n matrices with ``dims`` (length n+1, matrix i is dims[i] x dims[i+1]):

    m[i][j] = min over i<=k<j of m[i][k] + m[k+1][j]
                              + dims[i] * dims[k+1] * dims[j+1]

Fill by increasing chain length. Time O(n^3), space O(n^2).
``dims`` must have length >= 2; ``ValueError`` is raised otherwise.
"""

import ast
import sys
from pathlib import Path
from typing import List, Sequence

ALGO_47_VERSION = "algo-47.v1"

STDLIB_USED = frozenset({"ast", "pathlib", "sys", "typing"})


def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every imported top-level module
    is one this module actually uses from the standard library."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    stdlib_names = set(sys.stdlib_module_names)
    for name in sorted(imported):
        assert name in stdlib_names, "non-stdlib import: %s" % name
        assert name in STDLIB_USED, "imported but unused module: %s" % name
    assert set(STDLIB_USED) == imported, (
        "import drift: declared %s vs found %s"
        % (sorted(STDLIB_USED), sorted(imported))
    )
    return True


def matrix_chain(dims: Sequence[int]) -> int:
    """Return the minimum number of scalar multiplications for the chain."""
    dims = list(dims)
    n = len(dims) - 1
    if n < 1:
        raise ValueError("dims must have length >= 2, got %r" % (dims,))
    for d in dims:
        if d <= 0:
            raise ValueError("dims must be positive, got %r" % (d,))
    m: List[List[int]] = [[0] * n for _ in range(n)]
    for length in range(2, n + 1):
        for i in range(n - length + 1):
            j = i + length - 1
            best = None
            for k in range(i, j):
                cost = m[i][k] + m[k + 1][j] + dims[i] * dims[k + 1] * dims[j + 1]
                if best is None or cost < best:
                    best = cost
            m[i][j] = best if best is not None else 0
    return m[0][n - 1]


def main() -> None:
    assert matrix_chain([1, 2, 3, 4]) == 18
    assert matrix_chain([2, 3, 4]) == 24
    assert matrix_chain([3, 5]) == 0
    assert matrix_chain([10, 30, 5, 60]) == 4500
    assert matrix_chain([40, 20, 30, 10, 30]) == 26000
    try:
        matrix_chain([5])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for len(dims) < 2")
    assert stdlib_only()
    print("algo-47 OK")


if __name__ == "__main__":
    main()
