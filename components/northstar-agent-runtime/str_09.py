"""Trie: prefix tree for strings.

Insert/search/starts_with in O(k) per word with per-word occurrence counts.

What this IS: a real dict-children trie.
What this IS NOT: a compressed (radix) trie.
"""

from __future__ import annotations

import ast

#: Module version.
STR_09_VERSION = "str-trie.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-trie.v1"


class StrError(Exception):
    """Fail-closed."""


class TrieNode:
    __slots__ = ("children", "is_end", "count")

    def __init__(self) -> None:
        self.children = {}
        self.is_end = False
        self.count = 0


class Trie:
    """Prefix tree."""

    def __init__(self) -> None:
        self.root = TrieNode()

    def insert(self, word: str) -> None:
        node = self.root
        for ch in word:
            node = node.children.setdefault(ch, TrieNode())
        node.is_end = True
        node.count += 1

    def _find(self, s: str):
        node = self.root
        for ch in s:
            node = node.children.get(ch)
            if node is None:
                return None
        return node

    def search(self, word: str) -> bool:
        node = self._find(word)
        return node is not None and node.is_end

    def starts_with(self, prefix: str) -> bool:
        return self._find(prefix) is not None

    def count_words(self, word: str) -> int:
        node = self._find(word)
        return node.count if node else 0


def test_trie_search():
    t = Trie()
    t.insert("apple")
    assert t.search("apple") is True
    assert t.search("app") is False


def test_trie_prefix():
    t = Trie()
    t.insert("apple")
    assert t.starts_with("app") is True
    assert t.starts_with("apl") is False


def test_trie_count():
    t = Trie()
    t.insert("a")
    t.insert("a")
    assert t.count_words("a") == 2
    assert t.count_words("b") == 0


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
    test_trie_search()
    test_trie_prefix()
    test_trie_count()
    assert stdlib_only()
    print("str-09 OK: trie")


if __name__ == "__main__":
    main()
