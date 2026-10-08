"""Group anagrams: sorted-key bucketing.

Buckets words by their sorted-character key in O(n * k log k).

What this IS: a real grouping implementation.
What this IS NOT: prime-product hashing keys.
"""

from __future__ import annotations

import ast

#: Module version.
STR_30_VERSION = "str-group-anagrams.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-group-anagrams.v1"


class StrError(Exception):
    """Fail-closed."""


def group_anagrams(words: list) -> list:
    """Group words into anagram classes."""
    groups = {}
    for w in words:
        key = "".join(sorted(w))
        groups.setdefault(key, []).append(w)
    return list(groups.values())


def _norm(groups):
    return sorted(sorted(g) for g in groups)


def test_group_basic():
    assert _norm(group_anagrams(["eat", "tea", "tan", "ate", "nat", "bat"])) == [
        ["ate", "eat", "tea"], ["bat"], ["nat", "tan"]]


def test_group_empty():
    assert group_anagrams([]) == []


def test_group_single():
    assert group_anagrams(["a"]) == [["a"]]


def test_group_none():
    assert _norm(group_anagrams(["ab", "cd"])) == [["ab"], ["cd"]]


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
    test_group_basic()
    test_group_empty()
    test_group_single()
    test_group_none()
    assert stdlib_only()
    print("str-30 OK: group-anagrams")


if __name__ == "__main__":
    main()
