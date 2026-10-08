"""DS: KD-Tree (37/50). k-dimensional tree"""
from __future__ import annotations

import ast

#: Module version.
DS_37_VERSION = "ds-37-kd-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-37.kd-tree.v1"


class _KDNode:
    __slots__ = ("point", "left", "right", "axis")

    def __init__(self, point, left, right, axis):
        self.point = point
        self.left = left
        self.right = right
        self.axis = axis


class KDTree:
    """KD-tree with nearest-neighbor search."""

    def __init__(self, points, k=2):
        self.k = k
        self.root = self._build([tuple(p) for p in points], 0)

    def _build(self, points, depth):
        if not points:
            return None
        axis = depth % self.k
        points.sort(key=lambda p: p[axis])
        mid = len(points) // 2
        return _KDNode(
            points[mid],
            self._build(points[:mid], depth + 1),
            self._build(points[mid + 1:], depth + 1),
            axis,
        )

    def nearest(self, target):
        """Return the nearest point to ``target`` (None if empty)."""
        target = tuple(target)
        best = [None, float("inf")]

        def dist2(a, b):
            return sum((x - y) ** 2 for x, y in zip(a, b))

        def rec(node):
            if node is None:
                return
            d = dist2(node.point, target)
            if d < best[1]:
                best[0] = node.point
                best[1] = d
            axis = node.axis
            diff = target[axis] - node.point[axis]
            if diff < 0:
                near, far = node.left, node.right
            else:
                near, far = node.right, node.left
            rec(near)
            if diff * diff < best[1]:
                rec(far)

        rec(self.root)
        return best[0]

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
    t = KDTree([(0, 0), (5, 5), (2, 1), (9, 9)])
    assert t.nearest((1, 1)) == (2, 1)
    assert t.nearest((8, 8)) == (9, 9)
    assert KDTree([]).nearest((0, 0)) is None
    assert stdlib_only()
    print("ds-37 OK: nearest-neighbor search")


if __name__ == "__main__":
    main()
