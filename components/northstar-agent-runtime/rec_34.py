"""Grid paths: paths(r-1,c) + paths(r,c-1)

Counts right/down paths from (0,0) to (r,c); edges have exactly one path.

What this IS: a real recursive lattice-path counter, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_34_VERSION = "rec-grid-paths.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-grid-paths.v1"


class RecError(Exception):
    """Fail-closed."""


def paths(r: int, c: int) -> int:
    """Right/down paths to (r, c). Fail-closed on negatives."""
    if r < 0 or c < 0:
        raise RecError("paths needs r, c >= 0")
    if r == 0 or c == 0:
        return 1
    return paths(r - 1, c) + paths(r, c - 1)

def test_paths_basic():
    assert paths(2, 2) == 6


def test_paths_edge():
    assert paths(0, 5) == 1


def test_paths_one():
    assert paths(3, 1) == 4


def test_paths_negative_raises():
    try:
        paths(-1, 2)
    except RecError:
        return
    raise AssertionError("expected RecError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_paths_basic()
    test_paths_edge()
    test_paths_one()
    test_paths_negative_raises()
    assert stdlib_only()
    print("rec-grid-paths OK")


if __name__ == "__main__":
    main()
