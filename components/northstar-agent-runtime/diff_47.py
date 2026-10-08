"""Difference Array Reconstruction: difference array example.

Given a difference array with a zero sentinel, recover the original values; validate the sentinel fail-closed. Also builds diffs.

What this IS: real diff construction and validated reconstruction, fail-closed on bad sentinels
What this IS NOT: reconstruction without sentinel validation
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_47_VERSION = "diff-reconstruct.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-diff-reconstruct.v1"


class DiffError(Exception):
    """Fail-closed."""


def make_diff(values: list) -> list:
    """Build a difference array with a zero sentinel."""
    d = [0] * (len(values) + 1)
    prev = 0
    for i, v in enumerate(values):
        d[i] = v - prev
        prev = v
    return d


def reconstruct(diff_arr: list) -> list:
    """Recover values; fail-closed unless the sentinel is zero."""
    if len(diff_arr) < 2:
        raise DiffError("need length >= 2")
    if diff_arr[-1] != 0:
        raise DiffError("sentinel must be 0")
    out = []
    cur = 0
    for v in diff_arr[:-1]:
        cur += v
        out.append(cur)
    return out

def test_roundtrip():
    assert reconstruct(make_diff([3, 1, 4])) == [3, 1, 4]


def test_roundtrip_zeros():
    assert reconstruct(make_diff([0, 0, 5])) == [0, 0, 5]


def test_bad_sentinel():
    try:
        reconstruct([3, -2, 3, 9])
    except DiffError:
        return
    raise AssertionError("expected DiffError")


def test_too_short():
    try:
        reconstruct([5])
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
    test_roundtrip()
    test_roundtrip_zeros()
    test_bad_sentinel()
    test_too_short()
    assert stdlib_only()
    print("diff-47 OK: diff-reconstruct")


if __name__ == "__main__":
    main()
