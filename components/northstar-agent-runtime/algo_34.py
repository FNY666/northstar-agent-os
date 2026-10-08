"""Trie (prefix tree) for lowercase a-z words.

A trie stores words character-by-character in a tree: each edge is a
letter, and nodes mark word endings. Sharing common prefixes makes
prefix queries cheap.

Complexities (L = word/prefix length): insert O(L), search O(L),
starts_with O(L) to reach the prefix node.

Assumes words consist of lowercase letters a-z only; other characters
raise ValueError.
"""

from __future__ import annotations

import ast
import sys
from typing import Dict, List

ALGO_34_VERSION = "algo-34.v1"


class _Node:
    __slots__ = ("children", "is_word")

    def __init__(self) -> None:
        self.children: Dict[str, "_Node"] = {}
        self.is_word = False


def _check(word: str) -> None:
    if not isinstance(word, str):
        raise TypeError("word must be a str")
    for ch in word:
        if not ("a" <= ch <= "z"):
            raise ValueError(f"only lowercase a-z allowed, got {word!r}")


class Trie:
    """Prefix tree over lowercase a-z words."""

    def __init__(self) -> None:
        self._root = _Node()
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def insert(self, word: str) -> None:
        """Insert a word. Re-inserting is a no-op."""
        _check(word)
        node = self._root
        for ch in word:
            child = node.children.get(ch)
            if child is None:
                child = _Node()
                node.children[ch] = child
            node = child
        if not node.is_word:
            node.is_word = True
            self._size += 1

    def search(self, word: str) -> bool:
        """Return True only for exact word matches."""
        _check(word)
        node = self._root
        for ch in word:
            node = node.children.get(ch)  # type: ignore[assignment]
            if node is None:
                return False
        return node.is_word

    def starts_with(self, prefix: str) -> bool:
        """Return True if any inserted word starts with prefix."""
        _check(prefix)
        node = self._root
        for ch in prefix:
            node = node.children.get(ch)  # type: ignore[assignment]
            if node is None:
                return False
        return True

    def words_with_prefix(self, prefix: str) -> List[str]:
        """Return all inserted words starting with prefix (helper)."""
        _check(prefix)
        node = self._root
        for ch in prefix:
            node = node.children.get(ch)  # type: ignore[assignment]
            if node is None:
                return []
        out: List[str] = []

        def dfs(n: _Node, path: List[str]) -> None:
            if n.is_word:
                out.append("".join(path))
            for ch in sorted(n.children):
                path.append(ch)
                dfs(n.children[ch], path)
                path.pop()

        dfs(node, list(prefix))
        return out


def stdlib_only() -> bool:
    """Assert every imported top-level module is from the stdlib."""
    src = open(__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in stdlib, node.module
    return True


def main() -> None:
    t = Trie()
    assert not t.search("a")
    assert not t.starts_with("a")
    for w in ["apple", "app", "apricot", "banana"]:
        t.insert(w)
    assert t.search("apple") and t.search("app")
    assert not t.search("appl")  # prefix but not a word
    assert not t.search("application")
    assert t.starts_with("app") and t.starts_with("b") and t.starts_with("")
    assert not t.starts_with("z")
    assert len(t) == 4
    t.insert("apple")  # duplicate: no-op
    assert len(t) == 4
    assert t.words_with_prefix("ap") == ["app", "apple", "apricot"]
    try:
        t.insert("Apple")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("algo_34 OK")


if __name__ == "__main__":
    main()
