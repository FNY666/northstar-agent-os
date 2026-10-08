"""psum_18: Prefix Sum of Squares (Variance)

Sum and sum-of-squares prefixes give range variance in O(1).

Time complexity: O(n) build, O(1) query
Space complexity: O(n)"""

import ast
import sys
PSUM_18_VERSION = "psum-18.v1"


def build(a):
    ps = [0]
    psq = [0]
    for x in a:
        ps.append(ps[-1] + x)
        psq.append(psq[-1] + x * x)
    return ps, psq


def variance(p, l, r):
    ps, psq = p
    n = r - l + 1
    s = ps[r + 1] - ps[l]
    q = psq[r + 1] - psq[l]
    return (q - s * s / n) / n

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
    p = build([1, 2, 3, 4])
    assert abs(variance(p, 0, 3) - 1.25) < 1e-9
    assert variance(p, 1, 1) == 0.0
    assert abs(variance(p, 0, 1) - 0.25) < 1e-9
    p = build([5])
    assert variance(p, 0, 0) == 0.0
    assert stdlib_only()
    print("psum_18 OK")


if __name__ == "__main__":
    main()
