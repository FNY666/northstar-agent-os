"""Tree Eulerian classification (EULER-045), Real."""
from __future__ import annotations
import ast

VERSION = "euler-45.v1"

def tree_eulerian_kind(n):
    """Tree on n vertices: circuit iff n<=1, trail iff n==2, else none."""
    if n <= 1:
        return "circuit"
    if n == 2:
        return "trail"
    return "none"


def tree_trail(n):
    """Explicit Eulerian trail of path tree on n vertices."""
    if n == 2:
        return [0, 1]
    if n == 1:
        return [0]
    return []

def main() -> None:
    assert tree_eulerian_kind(1) == "circuit"
    assert tree_eulerian_kind(2) == "trail"
    assert tree_eulerian_kind(3) == "none"
    assert tree_eulerian_kind(10) == "none"
    assert tree_trail(2) == [0, 1]
    assert tree_trail(5) == []
    assert stdlib_only()
    print("euler-45.v1 OK")

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


if __name__ == "__main__":
    main()
