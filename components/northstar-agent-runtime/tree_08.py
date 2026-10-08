"""Suffix trie (mock of suffix tree): all-suffix trie, substring search. Stdlib only."""
from __future__ import annotations
from typing import Dict

class SNode:
    __slots__ = ("children", "count")
    def __init__(self) -> None:
        self.children: Dict[str, "SNode"] = {}
        self.count = 0  # number of suffixes passing through

class SuffixTrie:
    def __init__(self, text: str) -> None:
        self.root = SNode()
        self.text = text
        for i in range(len(text)):
            self._insert_suffix(i)
    def _insert_suffix(self, i: int) -> None:
        n = self.root
        for ch in self.text[i:]:
            n = n.children.setdefault(ch, SNode())
            n.count += 1
    def contains(self, pattern: str) -> bool:
        n = self.root
        for ch in pattern:
            n = n.children.get(ch)
            if n is None: return False
        return True
    def occurrences(self, pattern: str) -> int:
        n = self.root
        for ch in pattern:
            n = n.children.get(ch)
            if n is None: return 0
        return n.count

def main() -> None:
    st = SuffixTrie("banana")
    assert st.contains("ana") and st.contains("ban")
    assert not st.contains("nab")
    assert st.occurrences("ana") == 2
    assert st.occurrences("a") == 3
    print("tree_08 Suffix trie (mock) OK")

if __name__ == "__main__":
    main()
