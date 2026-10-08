"""dac-08: Karatsuba multiplication.

Divide-and-conquer integer multiplication in O(n^1.585) via three half-size products.
"""
import ast
import sys

DAC_08_VERSION = "dac-08.v1"

def karatsuba(x, y):
    """Karatsuba multiplication for non-negative ints."""
    if x < 0 or y < 0:
        raise ValueError("non-negative integers only")
    if x < 10 or y < 10:
        return x * y
    n = max(len(str(x)), len(str(y)))
    m = n // 2
    high1, low1 = divmod(x, 10 ** m)
    high2, low2 = divmod(y, 10 ** m)
    z0 = karatsuba(low1, low2)
    z2 = karatsuba(high1, high2)
    z1 = karatsuba(low1 + high1, low2 + high2) - z2 - z0
    return z2 * 10 ** (2 * m) + z1 * 10 ** m + z0

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
    assert karatsuba(0, 12345) == 0
    assert karatsuba(7, 8) == 56
    assert karatsuba(1234, 5678) == 1234 * 5678
    assert karatsuba(123456789, 987654321) == 123456789 * 987654321
    assert karatsuba(10 ** 20 + 1, 10 ** 20 + 3) == (10 ** 20 + 1) * (10 ** 20 + 3)
    try:
        karatsuba(-1, 5)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-08 OK")


if __name__ == "__main__":
    main()
