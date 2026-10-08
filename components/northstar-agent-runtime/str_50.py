"""Suffix trie: naive all-suffixes trie.

Inserts every suffix; substring queries walk the trie in O(|p|).

What this IS: a real (naive, O(n^2) space) suffix trie.
What this IS NOT: suffix-tree compression to O(n) space.
"""

from __future__ import annotations

import ast

#: Module version.
STR_50_VERSION = "str-suffix-trie.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-suffix-trie.v1"


class StrError(Exception):
    """Fail-closed."""


class SuffixTrie:
    """Trie of all suffixes of a text."""

    def __init__(self, text: str) -> None:
        self.root = {}
        for i in range(len(text)):
            node = self.root
            for ch in text[i:]:
                node = node.setdefault(ch, {})
            node["$"] = i

    def contains(self, pattern: str) -> bool:
        """True iff pattern occurs in the text."""
        node = self.root
        for ch in pattern:
            if ch not in node:
                return False
            node = node[ch]
        return True

    def occurrences(self, pattern: str) -> list:
        """Start indices of all occurrences of pattern."""
        node = self.root
        for ch in pattern:
            if ch not in node:
                return []
            node = node[ch]
        res = []

        def collect(nd):
            for k, v in nd.items():
                if k == "$":
                    res.append(v)
                else:
                    collect(v)

        collect(node)
        return sorted(res)


def test_st_contains():
    st = SuffixTrie("banana")
    assert st.contains("ana") is True
    assert st.contains("nan") is True
    assert st.contains("xyz") is False


def test_st_occurrences():
    st = SuffixTrie("banana")
    assert st.occurrences("ana") == [1, 3]


def test_st_missing():
    st = SuffixTrie("banana")
    assert st.occurrences("xyz") == []


def test_st_empty_text():
    st = SuffixTrie("")
    assert st.contains("a") is False


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
    test_st_contains()
    test_st_occurrences()
    test_st_missing()
    test_st_empty_text()
    assert stdlib_only()
    print("str-50 OK: suffix-trie")


if __name__ == "__main__":
    main()
