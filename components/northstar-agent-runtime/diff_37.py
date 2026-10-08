"""Validated Batch Range Add: difference array example.

Batch range adds with per-update validation: the first bad update aborts fail-closed, reporting its index.

What this IS: a real validating batch update, fail-closed with the bad index
What this IS NOT: applying updates without validation
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_37_VERSION = "validated-batch-add.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-validated-batch-add.v1"


class DiffError(Exception):
    """Fail-closed."""


def validated_batch_add(n: int, updates: list) -> list:
    """updates: list of (l, r, v). Fail-closed on the first bad update."""
    if n <= 0:
        raise DiffError("n must be > 0")
    d = [0] * (n + 1)
    for idx, (l, r, v) in enumerate(updates):
        if not (0 <= l <= r < n):
            raise DiffError("bad update at index %d" % idx)
        d[l] += v
        d[r + 1] -= v
    out = []
    cur = 0
    for i in range(n):
        cur += d[i]
        out.append(cur)
    return out

def test_basic():
    assert validated_batch_add(4, [(0, 1, 2), (2, 3, 3)]) == [2, 2, 3, 3]


def test_empty():
    assert validated_batch_add(3, []) == [0, 0, 0]


def test_bad_index_reported():
    try:
        validated_batch_add(4, [(0, 1, 2), (2, 9, 3)])
    except DiffError as e:
        assert "index 1" in str(e)
        return
    raise AssertionError("expected DiffError")


def test_bad_n():
    try:
        validated_batch_add(0, [])
    except DiffError:
        return
    raise AssertionError("expected DiffError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    test_basic()
    test_empty()
    test_bad_index_reported()
    test_bad_n()
    assert stdlib_only()
    print("diff-37 OK: validated-batch-add")


if __name__ == "__main__":
    main()
