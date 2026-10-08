"""Permutations: pick each head in turn

For each position, fix one element and permute the rest: n! results.

What this IS: a real recursive permutation generator.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_16_VERSION = "rec-permutations.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-permutations.v1"


class RecError(Exception):
    """Fail-closed."""


def perms(xs):
    """All permutations of xs as lists."""
    if not xs:
        return [[]]
    out = []
    for i, x in enumerate(xs):
        for p in perms(xs[:i] + xs[i + 1:]):
            out.append([x] + p)
    return out

def test_perms_empty():
    assert perms([]) == [[]]


def test_perms_count():
    assert len(perms([1, 2, 3])) == 6


def test_perms_content():
    assert sorted(perms([1, 2])) == [[1, 2], [2, 1]]

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
    test_perms_empty()
    test_perms_count()
    test_perms_content()
    assert stdlib_only()
    print("rec-permutations OK")


if __name__ == "__main__":
    main()
