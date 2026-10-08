"""Power set: each element in or out

Doubles the result set per element: 2^n subsets.

What this IS: a real recursive power-set generator.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_18_VERSION = "rec-powerset.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-powerset.v1"


class RecError(Exception):
    """Fail-closed."""


def powerset(xs):
    """All subsets of xs as lists."""
    if not xs:
        return [[]]
    rest = powerset(xs[1:])
    return rest + [[xs[0]] + s for s in rest]

def test_powerset_empty():
    assert powerset([]) == [[]]


def test_powerset_count():
    assert len(powerset([1, 2, 3])) == 8


def test_powerset_contains():
    assert [1, 3] in powerset([1, 2, 3])

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
    test_powerset_empty()
    test_powerset_count()
    test_powerset_contains()
    assert stdlib_only()
    print("rec-powerset OK")


if __name__ == "__main__":
    main()
