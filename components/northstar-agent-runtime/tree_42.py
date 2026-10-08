"""Ternary search tree: trie variant with 3-way nodes. Stdlib only."""
from __future__ import annotations
from typing import List, Optional

class TSTNode:
    __slots__ = ("ch", "left", "mid", "right", "is_end")
    def __init__(self, ch: str) -> None:
        self.ch = ch
        self.left: Optional["TSTNode"] = None
        self.mid: Optional["TSTNode"] = None
        self.right: Optional["TSTNode"] = None
        self.is_end = False

class TST:
    def __init__(self) -> None:
        self.root: Optional[TSTNode] = None
    def insert(self, word: str) -> None:
        self.root = self._put(self.root, word, 0)
    def _put(self, n, word, d):
        ch = word[d]
        if n is None: n = TSTNode(ch)
        if ch < n.ch: n.left = self._put(n.left, word, d)
        elif ch > n.ch: n.right = self._put(n.right, word, d)
        elif d < len(word) - 1: n.mid = self._put(n.mid, word, d + 1)
        else: n.is_end = True
        return n
    def search(self, word: str) -> bool:
        n, d = self.root, 0
        while n is not None:
            ch = word[d]
            if ch < n.ch: n = n.left
            elif ch > n.ch: n = n.right
            elif d == len(word) - 1: return n.is_end
            else: n, d = n.mid, d + 1
        return False
    def words(self) -> List[str]:
        out: List[str] = []
        def rec(n, cur):
            if n is None: return
            rec(n.left, cur)
            if n.is_end: out.append(cur + n.ch)
            rec(n.mid, cur + n.ch)
            rec(n.right, cur)
        rec(self.root, "")
        return sorted(out)

def main() -> None:
    t = TST()
    for w in ["cat", "car", "dog"]: t.insert(w)
    assert t.search("cat") and t.search("dog")
    assert not t.search("ca") and not t.search("cow")
    assert t.words() == ["car", "cat", "dog"]
    print("tree_42 Ternary search tree OK")

if __name__ == "__main__":
    main()
