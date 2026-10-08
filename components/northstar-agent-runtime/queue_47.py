"""reconstruct_queue: reconstruct queue by height: sort by (-height, k) then insert each at index k. IS: a reconstructed people list; malformed pairs raise ValueError. IS NOT: a segment-tree insertion order (this is the sort-then-insert version)."""

from __future__ import annotations

import ast
from typing import List
VERSION = "queue-47.v1"

def reconstruct_queue(people: List[List[int]]) -> List[List[int]]:
    """Rebuild the queue from ``[height, k]`` pairs."""
    if not isinstance(people, list):
        raise ValueError("people must be a list")
    for p in people:
        if (
            not isinstance(p, (list, tuple)) or len(p) != 2
            or isinstance(p[0], bool) or not isinstance(p[0], int) or p[0] < 0
            or isinstance(p[1], bool) or not isinstance(p[1], int) or p[1] < 0
        ):
            raise ValueError("each person must be [non-negative int height, non-negative int k]")
    ordered = sorted(people, key=lambda p: (-p[0], p[1]))
    out: List[List[int]] = []
    for h, k in ordered:
        if k > len(out):
            raise ValueError("k exceeds the number of taller-or-equal people placed")
        out.insert(k, [h, k])
    return out


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
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
    p = [[7, 0], [4, 4], [7, 1], [5, 0], [6, 1], [5, 2]]
    assert reconstruct_queue(p) == [[5, 0], [7, 0], [5, 2], [6, 1], [4, 4], [7, 1]]
    assert reconstruct_queue([]) == []
    assert reconstruct_queue([[5, 0]]) == [[5, 0]]
    try:
        reconstruct_queue([[7, 0], [5]])
    except ValueError:
        pass
    else:
        raise AssertionError("malformed pair must raise ValueError")
    try:
        reconstruct_queue([[5, 9]])
    except ValueError:
        pass
    else:
        raise AssertionError("impossible k must raise ValueError")
    assert stdlib_only()
    print("queue-47 OK: queue reconstruction by height")


if __name__ == "__main__":
    main()
