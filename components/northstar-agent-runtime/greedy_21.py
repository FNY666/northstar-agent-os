"""greedy_21: Reorganize string.

Always emit the currently most frequent remaining character with a max-heap.

Time complexity: O(n log k) time
Space complexity: O(k) auxiliary
"""

import ast
import sys
GREEDY_21_VERSION = "greedy-21.v1"


def reorganize_string(s):
    """Rearrange so no two adjacent characters are equal; return "" if impossible."""
    import heapq
    from collections import Counter
    if not s:
        return ""
    counts = Counter(s)
    heap = [(-c, ch) for ch, c in counts.items()]
    heapq.heapify(heap)
    res = []
    prev = (0, "")
    while heap:
        c, ch = heapq.heappop(heap)
        res.append(ch)
        if prev[0] < 0:
            heapq.heappush(heap, prev)
        prev = (c + 1, ch)
    out = "".join(res)
    if len(out) != len(s):
        return ""
    for i in range(len(out) - 1):
        if out[i] == out[i + 1]:
            return ""
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
    r = reorganize_string("aab")
    assert len(r) == 3 and r[0] != r[1] and r[1] != r[2]
    assert reorganize_string("aaab") == ""
    assert reorganize_string("") == ""
    assert reorganize_string("a") == "a"
    assert stdlib_only()
    print("greedy_21 OK")


if __name__ == "__main__":
    main()
