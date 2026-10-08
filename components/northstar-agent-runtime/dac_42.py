"""dac-42: Polynomial multiplication (divide and conquer).

Split p into low/high halves: p*q = p0*q + x^m * (p1*q). Coefficients lowest-first.
"""
import ast
import sys

DAC_42_VERSION = "dac-42.v1"

def _add_p(p, q):
    n = max(len(p), len(q))
    return [(p[i] if i < len(p) else 0) + (q[i] if i < len(q) else 0) for i in range(n)]


def poly_mul_dc(p, q):
    """Polynomial multiplication via divide and conquer."""
    p = list(p)
    q = list(q)
    if not p or not q:
        return []
    if len(p) == 1:
        return [p[0] * c for c in q]
    if len(q) == 1:
        return [q[0] * c for c in p]
    m = len(p) // 2
    p0, p1 = p[:m], p[m:]
    z0 = poly_mul_dc(p0, q)
    z1 = poly_mul_dc(p1, q)
    res = _add_p(z0, [0] * m + z1)
    while len(res) > 1 and res[-1] == 0:
        res.pop()
    return res

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
    assert poly_mul_dc([], [1, 2]) == []
    assert poly_mul_dc([3], [1, 2]) == [3, 6]
    assert poly_mul_dc([1, 1], [1, 1]) == [1, 2, 1]
    assert poly_mul_dc([1, 2, 3], [4, 5]) == [4, 13, 22, 15]
    assert poly_mul_dc([2, 0, 1], [3, 1]) == [6, 2, 3, 1]
    assert stdlib_only()
    print("dac-42 OK")


if __name__ == "__main__":
    main()
