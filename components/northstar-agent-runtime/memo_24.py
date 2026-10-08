"""Memoized Interleaving String: memoization example.

Is s3 an interleave of s1 and s2? State (i, j) consumes s3[i+j] from either side. Length mismatch is fail-closed up front.

What this IS: a real memoized interleave checker, fail-closed on length mismatch.
What this IS NOT: an interleave enumerator; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_24_VERSION = "memo-interleaving-string.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-interleaving-string.v1"


class MemoError(Exception):
    """Fail-closed."""


def is_interleave(s1: str, s2: str, s3: str, i: int = 0, j: int = 0, _cache: dict | None = None) -> bool:
    """Memoized interleaving check. Fail-closed on length mismatch."""
    if len(s1) + len(s2) != len(s3):
        raise MemoError("is_interleave needs len(s1) + len(s2) == len(s3)")
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    k = i + j
    if k == len(s3):
        cache[key] = i == len(s1) and j == len(s2)
    else:
        ok = False
        if i < len(s1) and s1[i] == s3[k]:
            ok = ok or is_interleave(s1, s2, s3, i + 1, j, cache)
        if j < len(s2) and s2[j] == s3[k]:
            ok = ok or is_interleave(s1, s2, s3, i, j + 1, cache)
        cache[key] = ok
    return cache[key]

def test_is_interleave_true():
    assert is_interleave("aabcc", "dbbca", "aadbbcbcac") is True


def test_is_interleave_false():
    assert is_interleave("aabcc", "dbbca", "aadbbbaccc") is False


def test_is_interleave_mismatch_raises():
    try:
        is_interleave("a", "b", "abc")
    except MemoError:
        return
    raise AssertionError("expected MemoError")

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
    test_is_interleave_true()
    test_is_interleave_false()
    test_is_interleave_mismatch_raises()
    assert stdlib_only()
    print("memo-24 OK: interleaving-string")


if __name__ == "__main__":
    main()
