"""intv_49: Range module: add / query / remove (range_module).

Keep a sorted list of disjoint half-open intervals.

Time complexity: O(n) per op
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_49 = "intv-49.v1"


class RangeModule:
    """Track half-open [left, right) ranges with add/query/remove."""
    def __init__(self):
        self.ivs = []
    def add_range(self, left, right):
        new = []
        i = 0
        n = len(self.ivs)
        while i < n and self.ivs[i][1] < left:
            new.append(self.ivs[i]); i += 1
        while i < n and self.ivs[i][0] <= right:
            left = min(left, self.ivs[i][0]); right = max(right, self.ivs[i][1]); i += 1
        new.append([left, right])
        new.extend(self.ivs[i:])
        self.ivs = new
    def query_range(self, left, right):
        for s, e in self.ivs:
            if s <= left and e >= right:
                return True
        return False
    def remove_range(self, left, right):
        new = []
        for s, e in self.ivs:
            if e <= left or s >= right:
                new.append([s, e])
            else:
                if s < left:
                    new.append([s, left])
                if e > right:
                    new.append([right, e])
        self.ivs = new


def range_module_demo(ops):
    rm = RangeModule()
    out = []
    for op, a, b in ops:
        if op == "add":
            rm.add_range(a, b); out.append(None)
        elif op == "query":
            out.append(rm.query_range(a, b))
        else:
            rm.remove_range(a, b); out.append(None)
    return out

def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True


def main() -> None:
    assert range_module_demo([("add", 10, 20), ("query", 10, 14), ("query", 13, 15), ("query", 16, 17), ("remove", 14, 16), ("query", 10, 14), ("query", 13, 15)]) == [None, True, True, True, None, True, False]
    assert range_module_demo([("add", 1, 5), ("query", 2, 3)]) == [None, True]
    assert range_module_demo([("query", 1, 2)]) == [False]
    assert range_module_demo([("add", 1, 3), ("add", 5, 7), ("remove", 2, 6), ("query", 1, 2), ("query", 5, 7)]) == [None, None, None, True, False]
    assert range_module_demo([("add", 1, 10), ("remove", 1, 10), ("query", 1, 10)]) == [None, None, False]
    assert stdlib_only()
    print("intv_49 OK")


if __name__ == "__main__":
    main()
