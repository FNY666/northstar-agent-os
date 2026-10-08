"""Link-cut tree (mock): dynamic forest, path aggregate via parent pointers. Stdlib only.

Mock: maintains a forest with path-sum queries by climbing parents;
real LCT uses splay-based preferred paths (documented).
"""
from __future__ import annotations
from typing import Dict, List, Optional

class LCNode:
    def __init__(self, vid: int, val: int = 0) -> None:
        self.vid = vid
        self.val = val
        self.parent: Optional["LCNode"] = None

class LinkCutMock:
    def __init__(self) -> None:
        self.nodes: Dict[int, LCNode] = {}
    def make(self, vid: int, val: int = 0) -> None:
        self.nodes[vid] = LCNode(vid, val)
    def link(self, child: int, parent: int) -> None:
        self.nodes[child].parent = self.nodes[parent]
    def cut(self, vid: int) -> None:
        self.nodes[vid].parent = None
    def path_sum(self, vid: int) -> int:
        s, n = 0, self.nodes[vid]
        while n is not None:
            s += n.val; n = n.parent
        return s
    def root_of(self, vid: int) -> int:
        n = self.nodes[vid]
        while n.parent is not None: n = n.parent
        return n.vid

def main() -> None:
    lc = LinkCutMock()
    for i, v in enumerate([1, 2, 3, 4]): lc.make(i, v)
    lc.link(1, 0); lc.link(2, 1); lc.link(3, 1)
    assert lc.path_sum(2) == 6
    assert lc.root_of(3) == 0
    lc.cut(1)
    assert lc.root_of(2) == 1 and lc.path_sum(2) == 5
    print("tree_15 Link-cut (mock) OK")

if __name__ == "__main__":
    main()
