"""psum_20: Frequency Prefix (Value Counts)

Per-value prefix counts answer 'how many v in [l..r]' in O(1).

Time complexity: O(m*n) build, O(1) query
Space complexity: O(m*n)"""

import ast
import sys
PSUM_20_VERSION = "psum-20.v1"


def build(a):
    vals = sorted(set(a))
    idx = {v: i for i, v in enumerate(vals)}
    n = len(a)
    m = len(vals)
    p = [[0] * (n + 1) for _ in range(m)]
    for i, x in enumerate(a, 1):
        for j in range(m):
            p[j][i] = p[j][i - 1]
        p[idx[x]][i] += 1
    return vals, p


def count(vp, v, l, r):
    vals, p = vp
    j = vals.index(v)
    return p[j][r + 1] - p[j][l]

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
    vp = build([1, 2, 1, 3, 2, 1])
    assert count(vp, 1, 0, 5) == 3
    assert count(vp, 2, 1, 4) == 2
    assert count(vp, 3, 0, 2) == 0
    assert count(vp, 3, 3, 3) == 1
    assert stdlib_only()
    print("psum_20 OK")


if __name__ == "__main__":
    main()
