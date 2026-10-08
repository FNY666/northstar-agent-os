"""DS: Quadtree (38/50). quadtree (2D spatial index)"""
from __future__ import annotations

import ast

#: Module version.
DS_38_VERSION = "ds-38-quadtree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-38.quadtree.v1"


class QuadTree:
    """Point quadtree with capacity-based subdivision."""

    def __init__(self, x, y, w, h, capacity=4):
        self.bounds = (x, y, w, h)
        self.capacity = capacity
        self.points = []
        self.divided = False
        self.nw = self.ne = self.sw = self.se = None

    def _contains(self, p):
        x, y, w, h = self.bounds
        return x <= p[0] < x + w and y <= p[1] < y + h

    def insert(self, p):
        if not self._contains(p):
            return False
        if not self.divided and len(self.points) < self.capacity:
            self.points.append(p)
            return True
        if not self.divided:
            self._subdivide()
        return (self.nw.insert(p) or self.ne.insert(p)
                or self.sw.insert(p) or self.se.insert(p))

    def _subdivide(self):
        x, y, w, h = self.bounds
        hw, hh = w / 2, h / 2
        self.nw = QuadTree(x, y, hw, hh, self.capacity)
        self.ne = QuadTree(x + hw, y, hw, hh, self.capacity)
        self.sw = QuadTree(x, y + hh, hw, hh, self.capacity)
        self.se = QuadTree(x + hw, y + hh, hw, hh, self.capacity)
        self.divided = True
        pts, self.points = self.points, []
        for p in pts:
            self.insert(p)

    def query_range(self, qx, qy, qw, qh):
        out = []
        x, y, w, h = self.bounds
        if qx >= x + w or qx + qw <= x or qy >= y + h or qy + qh <= y:
            return out
        for p in self.points:
            if qx <= p[0] < qx + qw and qy <= p[1] < qy + qh:
                out.append(p)
        if self.divided:
            for child in (self.nw, self.ne, self.sw, self.se):
                out.extend(child.query_range(qx, qy, qw, qh))
        return out

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
    q = QuadTree(0, 0, 100, 100, capacity=2)
    pts = [(10, 10), (20, 20), (80, 80), (90, 90), (15, 15)]
    for p in pts:
        assert q.insert(p) is True
    assert q.insert((200, 200)) is False
    found = q.query_range(0, 0, 30, 30)
    assert sorted(found) == [(10, 10), (15, 15), (20, 20)]
    assert q.query_range(70, 70, 30, 30) == [(80, 80), (90, 90)] or sorted(q.query_range(70, 70, 30, 30)) == [(80, 80), (90, 90)]
    assert stdlib_only()
    print("ds-38 OK: capacity subdivision, range query")


if __name__ == "__main__":
    main()
