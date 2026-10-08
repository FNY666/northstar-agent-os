"""Paged binary tree (mock): external-memory BST with page buffering. Stdlib only."""
from __future__ import annotations
from typing import Dict, List, Optional

PAGE = 3  # keys per page (tiny for testing)

class Page:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.keys: List[int] = []
        self.left: Optional[int] = None
        self.right: Optional[int] = None

class PagedBSTMock:
    def __init__(self) -> None:
        self.pages: Dict[int, Page] = {}
        self.root: Optional[int] = None
        self._next = 0
        self.page_loads = 0
    def _new_page(self) -> Page:
        p = Page(self._next); self.pages[self._next] = p
        self._next += 1; return p
    def _load(self, pid: int) -> Page:
        self.page_loads += 1
        return self.pages[pid]
    def insert(self, key: int) -> None:
        if self.root is None:
            p = self._new_page(); p.keys = [key]; self.root = p.pid; return
        self._ins(self.root, key)
    def _ins(self, pid: int, key: int) -> None:
        p = self._load(pid)
        if key in p.keys: return
        if len(p.keys) < PAGE:
            p.keys.append(key); p.keys.sort(); return
        if key < p.keys[0]:
            if p.left is None:
                c = self._new_page(); c.keys = [key]; p.left = c.pid
            else: self._ins(p.left, key)
        elif key > p.keys[-1]:
            if p.right is None:
                c = self._new_page(); c.keys = [key]; p.right = c.pid
            else: self._ins(p.right, key)
        else:
            # within range but page full: split page (mock)
            mid = len(p.keys) // 2
            newp = self._new_page()
            newp.keys = p.keys[mid:]
            p.keys = sorted(p.keys[:mid] + [key])
            newp.right = p.right
            p.right = newp.pid
    def search(self, key: int) -> bool:
        pid = self.root
        while pid is not None:
            p = self._load(pid)
            if key in p.keys: return True
            pid = p.left if key < p.keys[0] else p.right
        return False
    def all_keys(self) -> List[int]:
        out: List[int] = []
        def rec(pid):
            if pid is None: return
            p = self._load(pid)
            rec(p.left); out.extend(p.keys); rec(p.right)
        rec(self.root); return out

def main() -> None:
    b = PagedBSTMock()
    for k in [5, 2, 8, 1, 9, 3]: b.insert(k)
    assert b.all_keys() == [1, 2, 3, 5, 8, 9]
    assert b.search(8) and not b.search(7)
    assert b.page_loads > 0
    print("tree_49 Paged BST (mock) OK")

if __name__ == "__main__":
    main()
