"""Range Addition Final Array: difference array example.

LeetCode 370: length and updates (l, r, v); return the modified array via a single difference pass.

What this IS: the real O(n+q) range-addition, fail-closed on bad updates
What this IS NOT: applying each update elementwise
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_17_VERSION = "range-addition-370.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-range-addition-370.v1"


class DiffError(Exception):
    """Fail-closed."""


def get_modified_array(length: int, updates: list) -> list:
    """updates: list of (l, r, v). Returns the final array."""
    if length < 0:
        raise DiffError("length must be >= 0")
    diff = [0] * (length + 1)
    for l, r, v in updates:
        if not (0 <= l <= r < length):
            raise DiffError("bad update")
        diff[l] += v
        diff[r + 1] -= v
    out = []
    cur = 0
    for i in range(length):
        cur += diff[i]
        out.append(cur)
    return out

def test_example():
    assert get_modified_array(5, [[1, 3, 2], [2, 4, 3], [0, 2, -2]]) == [-2, 0, 3, 5, 3]


def test_no_updates():
    assert get_modified_array(3, []) == [0, 0, 0]


def test_empty():
    assert get_modified_array(0, []) == []


def test_bad_update():
    try:
        get_modified_array(3, [[0, 3, 1]])
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
    test_example()
    test_no_updates()
    test_empty()
    test_bad_update()
    assert stdlib_only()
    print("diff-17 OK: range-addition-370")


if __name__ == "__main__":
    main()
