"""bs_47: Ternary search maximum

Find the integer maximizer of a unimodal function on [lo, hi]
by ternary search.

Time complexity: O(log(hi-lo)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_47_VERSION = "bs-47.v1"


def ternary_max(f, lo, hi):
    """Return the integer in [lo, hi] maximizing unimodal f."""
    while hi - lo > 2:
        m1 = lo + (hi - lo) // 3
        m2 = hi - (hi - lo) // 3
        if f(m1) < f(m2):
            lo = m1 + 1
        else:
            hi = m2 - 1
    return max(range(lo, hi + 1), key=f)

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
    assert ternary_max(lambda x: -(x - 3) ** 2 + 10, 0, 10) == 3
    assert ternary_max(lambda x: -abs(x - 5), -10, 10) == 5
    assert ternary_max(lambda x: x * (10 - x), 0, 10) == 5
    assert ternary_max(lambda x: x, 0, 7) == 7
    assert stdlib_only()
    print("bs_47 OK")


if __name__ == "__main__":
    main()
