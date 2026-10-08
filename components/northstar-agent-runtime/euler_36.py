"""Star graph Eulerian check (EULER-036), Real."""
from __future__ import annotations
import ast

VERSION = "euler-36.v1"

def star_edges(n):
    """Star S_n: center 0 with n leaves."""
    return [(0, i) for i in range(1, n + 1)]


def star_eulerian_kind(n):
    """Classify: 'circuit' (n=0), 'trail' (n=1), 'none' otherwise."""
    if n == 0:
        return "circuit"
    if n == 1:
        return "trail"
    return "none"

def main() -> None:
    assert star_eulerian_kind(0) == "circuit"
    assert star_eulerian_kind(1) == "trail"
    assert star_eulerian_kind(2) == "none"
    assert star_eulerian_kind(5) == "none"
    assert len(star_edges(3)) == 3
    assert stdlib_only()
    print("euler-36.v1 OK")

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
