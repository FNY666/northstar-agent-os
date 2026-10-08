"""dac-23: Modular exponentiation.

(base**exp) % mod by squaring; the core of RSA/Diffie-Hellman. O(log exp).
"""
import ast
import sys

DAC_23_VERSION = "dac-23.v1"

def pow_mod(base, exp, mod):
    """(base**exp) % mod by squaring; mod > 0, exp >= 0."""
    if mod <= 0:
        raise ValueError("mod must be positive")
    if exp < 0:
        raise ValueError("exp must be non-negative")
    if exp == 0:
        return 1 % mod
    half = pow_mod(base, exp // 2, mod)
    r = (half * half) % mod
    if exp % 2:
        r = (r * base) % mod
    return r

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
    assert pow_mod(2, 10, 1000) == 24
    assert pow_mod(3, 0, 7) == 1
    assert pow_mod(5, 3, 13) == pow(5, 3, 13)
    assert pow_mod(123456, 789012, 1000003) == pow(123456, 789012, 1000003)
    try:
        pow_mod(2, 3, 0)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-23 OK")


if __name__ == "__main__":
    main()
