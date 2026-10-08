"""Quadtree: 2D point indexing with range queries. Stdlib only."""
from __future__ import annotations
from typing import List, Tuple

Point = Tuple[float, float]

class QuadNode:
    def __init__(self, x0, y0, x1, y1, cap: int = 4) -> None:
        self.bounds = (x0, y0, x1, y1)
        self.cap = cap
        self.points: List[Point] = []
        self.children: List["QuadNode"] = []
    def _subdivide(self) -> None:
        x0, y0, x1, y1 = self.bounds
        mx, my = (x0 + x1) / 2, (y0 + y1) / 2
        self.children = [
            QuadNode(x0, y0, mx, my, self.cap), QuadNode(mx, y0, x1, my, self.cap),
            QuadNode(x0, my, mx, y1, self.cap), QuadNode(mx, my, x1, y1, self.cap),
        ]
        for p in self.points:
            self._insert_child(p)
        self.points = []
    def _insert_child(self, p: Point) -> None:
        for c in self.children:
            x0, y0, x1, y1 = c.bounds
            if x0 <= p[0] <= x1 and y0 <= p[1] <= y1:
                c.insert(p); return
    def insert(self, p: Point) -> bool:
        x0, y0, x1, y1 = self.bounds
        if not (x0 <= p[0] <= x1 and y0 <= p[1] <= y1): return False
        if self.children:
            self._insert_child(p); return True
        self.points.append(p)
        if len(self.points) > self.cap:
            self._subdivide()
        return True
    def query(self, box) -> List[Point]:
        x0, y0, x1, y1 = self.bounds
        qx0, qy0, qx1, qy1 = box
        if x1 < qx0 or x0 > qx1 or y1 < qy0 or y0 > qy1: return []
        out = [p for p in self.points if qx0 <= p[0] <= qx1 and qy0 <= p[1] <= qy1]
        for c in self.children: out.extend(c.query(box))
        return out

def main() -> None:
    q = QuadNode(0, 0, 10, 10)
    for p in [(1, 1), (2, 2), (8, 8), (9, 9), (5, 5)]: q.insert(p)
    got = sorted(q.query((0, 0, 3, 3)))
    assert got == [(1, 1), (2, 2)]
    assert sorted(q.query((7, 7, 10, 10))) == [(8, 8), (9, 9)]
    assert q.insert((99, 99)) is False
    print("tree_18 Quadtree OK")

if __name__ == "__main__":
    main()
