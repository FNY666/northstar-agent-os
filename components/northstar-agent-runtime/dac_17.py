"""dac-17: Fast exponentiation.

x**n by squaring: halve the exponent each recursion. O(log n) multiplications.
"""
import ast
import sys

DAC_17_VERSION = "dac-17.v1"

def fast_pow(x, n):
    """x**n by squaring; n must be a non-negative int."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return 1
    half = fast_pow(x, n // 2)
    if n % 2 == 0:
        return half * half
    return half * half * x

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
    assert fast_pow(2, 0) == 1
    assert fast_pow(2, 10) == 1024
    assert fast_pow(3, 5) == 243
    assert fast_pow(5, 3) == 125
    assert fast_pow(1.5, 2) == 2.25
    try:
        fast_pow(2, -1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-17 OK")


if __name__ == "__main__":
    main()
