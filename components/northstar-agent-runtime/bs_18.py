"""bs_18: Square root with precision

Floating point square root of a non-negative number via binary
search to a configurable epsilon.

Time complexity: O(log(n/eps)) time
Space complexity: O(1) auxiliary"""

import ast
import sys
BS_18_VERSION = "bs-18.v1"


def sqrt_precise(n, eps=1e-7):
    """Return sqrt(n) within eps of the true value."""
    if n < 0:
        raise ValueError("n must be non-negative")
    lo, hi = 0.0, 1.0 if n < 1 else float(n)
    while hi - lo > eps:
        mid = (lo + hi) / 2
        if mid * mid <= n:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2

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
    assert abs(sqrt_precise(2) - 2 ** 0.5) < 1e-5
    assert abs(sqrt_precise(9) - 3.0) < 1e-5
    assert abs(sqrt_precise(0.25) - 0.5) < 1e-5
    assert abs(sqrt_precise(0) - 0.0) < 1e-5
    assert abs(sqrt_precise(100) - 10.0) < 1e-5
    assert stdlib_only()
    print("bs_18 OK")


if __name__ == "__main__":
    main()
