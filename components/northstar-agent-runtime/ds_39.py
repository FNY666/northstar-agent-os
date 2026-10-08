"""DS: Octree (39/50). octree (3D spatial index)"""
from __future__ import annotations

import ast

#: Module version.
DS_39_VERSION = "ds-39-octree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-39.octree.v1"


class Octree:
    """Point octree with capacity-based subdivision."""

    def __init__(self, x, y, z, w, h, d, capacity=4):
        self.bounds = (x, y, z, w, h, d)
        self.capacity = capacity
        self.points = []
        self.children = None

    def _contains(self, p):
        x, y, z, w, h, d = self.bounds
        return (x <= p[0] < x + w and y <= p[1] < y + h
                and z <= p[2] < z + d)

    def insert(self, p):
        if not self._contains(p):
            return False
        if self.children is None and len(self.points) < self.capacity:
            self.points.append(p)
            return True
        if self.children is None:
            self._subdivide()
        return any(c.insert(p) for c in self.children)

    def _subdivide(self):
        x, y, z, w, h, d = self.bounds
        hw, hh, hd = w / 2, h / 2, d / 2
        self.children = [
            Octree(x + dx * hw, y + dy * hh, z + dz * hd,
                   hw, hh, hd, self.capacity)
            for dx in (0, 1) for dy in (0, 1) for dz in (0, 1)
        ]
        pts, self.points = self.points, []
        for p in pts:
            self.insert(p)

    def query_range(self, qx, qy, qz, qw, qh, qd):
        out = []
        x, y, z, w, h, d = self.bounds
        if (qx >= x + w or qx + qw <= x or qy >= y + h or qy + qh <= y
                or qz >= z + d or qz + qd <= z):
            return out
        for p in self.points:
            if (qx <= p[0] < qx + qw and qy <= p[1] < qy + qh
                    and qz <= p[2] < qz + qd):
                out.append(p)
        if self.children:
            for c in self.children:
                out.extend(c.query_range(qx, qy, qz, qw, qh, qd))
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
    o = Octree(0, 0, 0, 100, 100, 100, capacity=2)
    for p in [(10, 10, 10), (90, 90, 90), (15, 15, 15)]:
        assert o.insert(p) is True
    assert o.insert((200, 0, 0)) is False
    assert sorted(o.query_range(0, 0, 0, 30, 30, 30)) == [(10, 10, 10), (15, 15, 15)]
    assert stdlib_only()
    print("ds-39 OK: 3D capacity subdivision, range query")


if __name__ == "__main__":
    main()
