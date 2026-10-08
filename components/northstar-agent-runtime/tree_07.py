"""Patricia trie (mock): compressed-edge trie. Stdlib only."""
from __future__ import annotations
from typing import Dict, List

class PNode:
    def __init__(self) -> None:
        self.edges: Dict[str, "PNode"] = {}
        self.is_end = False

class PatriciaTrie:
    def __init__(self) -> None:
        self.root = PNode()
        self.count = 0
    def insert(self, word: str) -> None:
        if not word: return
        node = self.root
        i = 0
        while i < len(word):
            for label, child in node.edges.items():
                # longest common prefix
                j = 0
                while j < len(label) and i + j < len(word) and label[j] == word[i + j]:
                    j += 1
                if j > 0:
                    if j < len(label):
                        # split edge
                        mid = PNode()
                        mid.edges[label[j:]] = child
                        mid.is_end = False
                        del node.edges[label]
                        node.edges[label[:j]] = mid
                        node = mid
                    else:
                        node = child
                    i += j
                    break
            else:
                node.edges[word[i:]] = PNode()
                node = node.edges[word[i:]]
                i = len(word)
        if not node.is_end:
            node.is_end = True
            self.count += 1
    def search(self, word: str) -> bool:
        node = self.root
        i = 0
        while i < len(word):
            for label, child in node.edges.items():
                if word.startswith(label, i):
                    i += len(label); node = child; break
            else:
                return False
        return node.is_end
    def words(self) -> List[str]:
        out: List[str] = []
        def rec(n, cur):
            if n.is_end: out.append(cur)
            for label in sorted(n.edges): rec(n.edges[label], cur + label)
        rec(self.root, "")
        return out

def main() -> None:
    p = PatriciaTrie()
    for w in ["test", "team", "toast"]: p.insert(w)
    assert p.search("test") and p.search("team") and p.search("toast")
    assert not p.search("te") and not p.search("tests")
    assert sorted(p.words()) == ["team", "test", "toast"]
    assert p.count == 3
    print("tree_07 Patricia trie (mock) OK")

if __name__ == "__main__":
    main()
