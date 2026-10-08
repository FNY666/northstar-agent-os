"""Octree: 3D point indexing. Stdlib only."""
from __future__ import annotations
from typing import List, Tuple

Point3 = Tuple[float, float, float]

class OctNode:
    def __init__(self, x0, y0, z0, x1, y1, z1, cap: int = 8) -> None:
        self.bounds = (x0, y0, z0, x1, y1, z1)
        self.cap = cap
        self.points: List[Point3] = []
        self.children: List["OctNode"] = []
    def _inside(self, p: Point3) -> bool:
        x0, y0, z0, x1, y1, z1 = self.bounds
        return x0 <= p[0] <= x1 and y0 <= p[1] <= y1 and z0 <= p[2] <= z1
    def _subdivide(self) -> None:
        x0, y0, z0, x1, y1, z1 = self.bounds
        mx, my, mz = (x0 + x1) / 2, (y0 + y1) / 2, (z0 + z1) / 2
        for dx in ((x0, mx), (mx, x1)):
            for dy in ((y0, my), (my, y1)):
                for dz in ((z0, mz), (mz, z1)):
                    self.children.append(OctNode(dx[0], dy[0], dz[0], dx[1], dy[1], dz[1], self.cap))
        for p in self.points:
            for c in self.children:
                if c._inside(p): c.insert(p); break
        self.points = []
    def insert(self, p: Point3) -> bool:
        if not self._inside(p): return False
        if self.children:
            for c in self.children:
                if c._inside(p): return c.insert(p)
            return False
        self.points.append(p)
        if len(self.points) > self.cap: self._subdivide()
        return True
    def count(self) -> int:
        return len(self.points) + sum(c.count() for c in self.children)
    def count_in_box(self, box) -> int:
        x0, y0, z0, x1, y1, z1 = self.bounds
        bx0, by0, bz0, bx1, by1, bz1 = box
        if x1 < bx0 or x0 > bx1 or y1 < by0 or y0 > by1 or z1 < bz0 or z0 > bz1:
            return 0
        n = sum(1 for p in self.points
                if bx0 <= p[0] <= bx1 and by0 <= p[1] <= by1 and bz0 <= p[2] <= bz1)
        return n + sum(c.count_in_box(box) for c in self.children)

def main() -> None:
    o = OctNode(0, 0, 0, 10, 10, 10, cap=2)
    pts = [(1, 1, 1), (2, 2, 2), (8, 8, 8), (9, 9, 9)]
    for p in pts: assert o.insert(p)
    assert o.count() == 4
    assert o.count_in_box((0, 0, 0, 3, 3, 3)) == 2
    assert o.count_in_box((7, 7, 7, 10, 10, 10)) == 2
    print("tree_19 Octree OK")

if __name__ == "__main__":
    main()
