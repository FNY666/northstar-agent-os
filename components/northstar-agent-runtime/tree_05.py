"""B+ tree (mock): leaf-linked ordered map. Stdlib only."""
from __future__ import annotations
from typing import List, Optional, Tuple

class Leaf:
    def __init__(self) -> None:
        self.items: List[Tuple[int, str]] = []
        self.next: Optional["Leaf"] = None

class BPlusTree:
    def __init__(self, order: int = 4) -> None:
        self.order = order
        self.head = Leaf()
    def insert(self, key: int, val: str) -> None:
        leaf = self._find_leaf(key)
        items = leaf.items
        i = 0
        while i < len(items) and items[i][0] < key: i += 1
        if i < len(items) and items[i][0] == key:
            items[i] = (key, val); return
        items.insert(i, (key, val))
        if len(items) > self.order - 1:
            self._split(leaf)
    def _find_leaf(self, key: int) -> Leaf:
        leaf = self.head
        while leaf.next is not None and leaf.next.items and leaf.next.items[0][0] <= key:
            leaf = leaf.next
        return leaf
    def _split(self, leaf: Leaf) -> None:
        mid = len(leaf.items) // 2
        new = Leaf()
        new.items = leaf.items[mid:]
        leaf.items = leaf.items[:mid]
        new.next = leaf.next
        leaf.next = new
    def get(self, key: int) -> Optional[str]:
        leaf = self._find_leaf(key)
        for k, v in leaf.items:
            if k == key: return v
        return None
    def scan(self) -> List[Tuple[int, str]]:
        out = []
        leaf = self.head
        while leaf is not None:
            out.extend(leaf.items); leaf = leaf.next
        return out

def main() -> None:
    bt = BPlusTree(order=4)
    for k in [5, 1, 9, 3, 7]:
        bt.insert(k, f"v{k}")
    assert [k for k, _ in bt.scan()] == [1, 3, 5, 7, 9]
    assert bt.get(7) == "v7" and bt.get(42) is None
    bt.insert(7, "new")
    assert bt.get(7) == "new"
    print("tree_05 B+ tree (mock) OK")

if __name__ == "__main__":
    main()
