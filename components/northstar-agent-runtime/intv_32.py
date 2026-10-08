"""intv_32: Merge k sorted interval lists (merge_k_lists).

Push each list head into a heap keyed by start; pop and refill.

Time complexity: O(n log k) time
Space complexity: O(k) auxiliary
"""

import ast
import sys

import heapq
INTV_32 = "intv-32.v1"


def merge_k_lists(lists):
    """Merge k sorted interval lists into one sorted list."""
    heap = []
    for li, lst in enumerate(lists):
        if lst:
            heapq.heappush(heap, (lst[0][0], lst[0][1], li, 0))
    res = []
    while heap:
        s, e, li, idx = heapq.heappop(heap)
        res.append((s, e))
        if idx + 1 < len(lists[li]):
            ns, ne = lists[li][idx + 1]
            heapq.heappush(heap, (ns, ne, li, idx + 1))
    return res

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
    assert merge_k_lists([[(1, 2), (5, 6)], [(3, 4)], [(0, 1), (7, 8)]]) == [(0, 1), (1, 2), (3, 4), (5, 6), (7, 8)]
    assert merge_k_lists([[], [(1, 1)]]) == [(1, 1)]
    assert merge_k_lists([]) == []
    assert merge_k_lists([[(2, 3)], [(1, 2)]]) == [(1, 2), (2, 3)]
    assert merge_k_lists([[(1, 5)], [(1, 2)], [(1, 3)]]) == [(1, 5), (1, 2), (1, 3)] or merge_k_lists([[(1, 5)], [(1, 2)], [(1, 3)]]) == [(1, 2), (1, 3), (1, 5)]
    assert stdlib_only()
    print("intv_32 OK")


if __name__ == "__main__":
    main()
