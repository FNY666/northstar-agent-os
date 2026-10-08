"""dac-29: Ternary search.

Shrink the interval by thirds around two interior points; for unimodal functions.
"""
import ast
import sys

DAC_29_VERSION = "dac-29.v1"

def ternary_search_max(f, lo, hi, eps=1e-9):
    """Approximate maximizer of unimodal f on [lo, hi]."""
    while hi - lo > eps:
        m1 = lo + (hi - lo) / 3
        m2 = hi - (hi - lo) / 3
        if f(m1) < f(m2):
            lo = m1
        else:
            hi = m2
    return (lo + hi) / 2

def stdlib_only() -> bool:
    # Parse this file with ast; every import must be a used stdlib module.
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
    f = lambda x: -(x - 2) ** 2 + 5
    assert abs(ternary_search_max(f, -10, 10) - 2) < 1e-6
    g = lambda x: -abs(x - 7) + 1
    assert abs(ternary_search_max(g, 0, 20) - 7) < 1e-6
    h = lambda x: x * (10 - x)
    assert abs(ternary_search_max(h, 0, 10) - 5) < 1e-6
    assert stdlib_only()
    print("dac-29 OK")


if __name__ == "__main__":
    main()
