"""psum_14: Range GCD (Sparse Table)

GCD is idempotent, so a sparse table answers range GCD in O(1).

Time complexity: O(n log n) build, O(1) query
Space complexity: O(n log n)"""

import ast
import sys
PSUM_14_VERSION = "psum-14.v1"


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def build(a):
    n = len(a)
    st = [a[:]]
    j = 1
    while (1 << j) <= n:
        prev = st[-1]
        step = 1 << (j - 1)
        st.append([_gcd(prev[i], prev[i + step]) for i in range(n - (1 << j) + 1)])
        j += 1
    return st


def range_gcd(st, l, r):
    j = (r - l + 1).bit_length() - 1
    return _gcd(st[j][l], st[j][r - (1 << j) + 1])

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
    st = build([6, 10, 15])
    assert range_gcd(st, 0, 2) == 1
    assert range_gcd(st, 0, 1) == 2
    assert range_gcd(st, 1, 2) == 5
    assert range_gcd(st, 0, 0) == 6
    assert _gcd(0, 7) == 7
    assert stdlib_only()
    print("psum_14 OK")


if __name__ == "__main__":
    main()
