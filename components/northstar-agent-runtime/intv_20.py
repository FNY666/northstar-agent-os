"""intv_20: Data stream as disjoint intervals (disjoint_stream).

Keep a sorted set of numbers; merge neighbours on each add.

Time complexity: O(n) per add
Space complexity: O(n) auxiliary
"""

import ast
import sys

import bisect
INTV_20 = "intv-20.v1"


class DisjointStream:
    """Stream of ints reported as disjoint sorted intervals."""
    def __init__(self):
        self.nums = []
    def add_num(self, val):
        i = bisect.bisect_left(self.nums, val)
        if i < len(self.nums) and self.nums[i] == val:
            return
        self.nums.insert(i, val)
    def get_intervals(self):
        res = []
        for x in self.nums:
            if res and x == res[-1][1] + 1:
                res[-1][1] = x
            else:
                res.append([x, x])
        return [tuple(r) for r in res]


def stream_intervals(vals):
    st = DisjointStream()
    out = []
    for v in vals:
        st.add_num(v)
        out.append(st.get_intervals())
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
    assert stream_intervals([1, 3, 7, 2, 6])[-1] == [(1, 3), (6, 7)]
    assert stream_intervals([1])[-1] == [(1, 1)]
    assert stream_intervals([1, 1, 1])[-1] == [(1, 1)]
    assert stream_intervals([5, 4, 3, 2, 1])[-1] == [(1, 5)]
    assert stream_intervals([]) == []
    assert stdlib_only()
    print("intv_20 OK")


if __name__ == "__main__":
    main()
