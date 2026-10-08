"""Z-algorithm: linear Z-box pattern matching.

Computes Z[i] = longest prefix match starting at i in O(n) using the [l, r] Z-box, then reads matches off pattern + '$' + text.

What this IS: a real O(n) Z implementation.
What this IS NOT: a streaming variant; this is batch.
"""

from __future__ import annotations

import ast

#: Module version.
STR_04_VERSION = "str-z-algorithm.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-z-algorithm.v1"


class StrError(Exception):
    """Fail-closed."""


def z_array(s: str) -> list:
    """Z[i] = length of longest substring starting at i matching the prefix."""
    n = len(s)
    z = [0] * n
    l = r = 0
    for i in range(1, n):
        if i <= r:
            z[i] = min(r - i + 1, z[i - l])
        while i + z[i] < n and s[z[i]] == s[i + z[i]]:
            z[i] += 1
        if i + z[i] - 1 > r:
            l, r = i, i + z[i] - 1
    if n:
        z[0] = n
    return z


def z_search(text: str, pattern: str) -> list:
    """Return start indices of all occurrences of pattern in text."""
    if not pattern:
        return []
    concat = pattern + "$" + text
    z = z_array(concat)
    m = len(pattern)
    return [i - m - 1 for i in range(m + 1, len(concat)) if z[i] >= m]


def test_z_array():
    assert z_array("aabcaabxaaaz") == [12, 1, 0, 0, 3, 1, 0, 0, 2, 2, 1, 0]


def test_z_search():
    assert z_search("abacaba", "aba") == [0, 4]


def test_z_none():
    assert z_search("hello", "world") == []


def test_z_empty():
    assert z_array("") == []


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
    test_z_array()
    test_z_search()
    test_z_none()
    test_z_empty()
    assert stdlib_only()
    print("str-04 OK: z-algorithm")


if __name__ == "__main__":
    main()
