"""Trie: prefix tree for strings. Stdlib only."""
from __future__ import annotations
from typing import Dict, List

class TrieNode:
    __slots__ = ("children", "is_end")
    def __init__(self) -> None:
        self.children: Dict[str, "TrieNode"] = {}
        self.is_end = False

class Trie:
    def __init__(self) -> None:
        self.root = TrieNode()
    def insert(self, word: str) -> None:
        n = self.root
        for ch in word:
            n = n.children.setdefault(ch, TrieNode())
        n.is_end = True
    def search(self, word: str) -> bool:
        n = self._walk(word)
        return n is not None and n.is_end
    def starts_with(self, prefix: str) -> bool:
        return self._walk(prefix) is not None
    def _walk(self, s: str):
        n = self.root
        for ch in s:
            n = n.children.get(ch)
            if n is None: return None
        return n
    def words_with_prefix(self, prefix: str) -> List[str]:
        n = self._walk(prefix)
        out: List[str] = []
        def rec(node, cur):
            if node.is_end: out.append(cur)
            for ch in sorted(node.children): rec(node.children[ch], cur + ch)
        if n is not None: rec(n, prefix)
        return out

def main() -> None:
    tr = Trie()
    for w in ["apple", "app", "banana"]: tr.insert(w)
    assert tr.search("app") and tr.search("apple")
    assert not tr.search("appl")
    assert tr.starts_with("ban")
    assert tr.words_with_prefix("app") == ["app", "apple"]
    print("tree_06 Trie OK")

if __name__ == "__main__":
    main()
