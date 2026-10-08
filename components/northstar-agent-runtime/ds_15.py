"""DS: Trie (15/50). prefix trie"""
from __future__ import annotations

import ast

#: Module version.
DS_15_VERSION = "ds-15-trie.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-15.trie.v1"


class _TrieNode:
    __slots__ = ("children", "is_end")

    def __init__(self):
        self.children = {}
        self.is_end = False


class Trie:
    """Prefix trie for string keys."""

    def __init__(self):
        self._root = _TrieNode()
        self._size = 0

    def insert(self, word):
        node = self._root
        for ch in word:
            child = node.children.get(ch)
            if child is None:
                child = _TrieNode()
                node.children[ch] = child
            node = child
        if not node.is_end:
            node.is_end = True
            self._size += 1

    def _find(self, text):
        node = self._root
        for ch in text:
            node = node.children.get(ch)
            if node is None:
                return None
        return node

    def search(self, word):
        node = self._find(word)
        return node is not None and node.is_end

    def starts_with(self, prefix):
        return self._find(prefix) is not None

    def __len__(self):
        return self._size

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
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
    t = Trie()
    t.insert("apple"); t.insert("app"); t.insert("banana")
    assert t.search("apple") is True
    assert t.search("app") is True
    assert t.search("appl") is False
    assert t.starts_with("appl") is True
    assert t.starts_with("ora") is False
    assert len(t) == 3
    assert stdlib_only()
    print("ds-15 OK: insert/search/starts_with")


if __name__ == "__main__":
    main()
