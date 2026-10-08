"""psum_25: Range Minimum (Sparse Table)

Min is idempotent, so a sparse table answers range minimum in O(1).

Time complexity: O(n log n) build, O(1) query
Space complexity: O(n log n)"""

import ast
import sys
PSUM_25_VERSION = "psum-25.v1"


def build(a):
    n = len(a)
    st = [a[:]]
    j = 1
    while (1 << j) <= n:
        prev = st[-1]
        step = 1 << (j - 1)
        st.append([min(prev[i], prev[i + step]) for i in range(n - (1 << j) + 1)])
        j += 1
    return st


def range_min(st, l, r):
    j = (r - l + 1).bit_length() - 1
    return min(st[j][l], st[j][r - (1 << j) + 1])

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
    st = build([5, 3, 4, 1, 2])
    assert range_min(st, 0, 2) == 3
    assert range_min(st, 3, 4) == 1
    assert range_min(st, 0, 4) == 1
    assert range_min(st, 2, 2) == 4
    assert stdlib_only()
    print("psum_25 OK")


if __name__ == "__main__":
    main()
