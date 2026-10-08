"""Celebrity Problem via candidate-elimination stack. IS: pairwise elimination on a stack then verification of the survivor. IS NOT: an O(n^2) scan of all pairs."""

from __future__ import annotations

import ast

VERSION = "stack-40.v1"

def _req_matrix(matrix: object) -> list[list[int]]:
    if not isinstance(matrix, list) or not matrix:
        raise ValueError("matrix must be a non-empty list")
    n = len(matrix)
    for row in matrix:
        if not isinstance(row, list) or len(row) != n:
            raise ValueError("matrix must be square")
        for v in row:
            if v not in (0, 1):
                raise ValueError("matrix must contain only 0/1")
    return [list(r) for r in matrix]


def celebrity(matrix: list[list[int]]) -> int:
    """Index of the celebrity, or -1 if none exists. Fail-closed."""
    m = _req_matrix(matrix)
    n = len(m)
    stack = list(range(n))
    while len(stack) > 1:
        a = stack.pop()
        b = stack.pop()
        if m[a][b]:
            stack.append(b)
        else:
            stack.append(a)
    cand = stack[0]
    for i in range(n):
        if i == cand:
            continue
        if m[cand][i] or not m[i][cand]:
            return -1
    return cand

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
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
    assert celebrity([[1, 1, 0], [0, 1, 0], [1, 1, 1]]) == 1
    assert celebrity([[1, 0], [0, 1]]) == -1
    assert celebrity([[1]]) == 0
    assert celebrity([[1, 1, 1], [1, 1, 1], [1, 1, 1]]) == -1
    try:
        celebrity([[1, 0], [0, 1, 0]])
    except ValueError:
        pass
    else:
        raise AssertionError("non-square must raise ValueError")
    assert stdlib_only()
    print("stack_40 OK")


if __name__ == "__main__":
    main()
