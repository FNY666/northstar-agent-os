"""wc_22: Substring matcher ('*literal*')

IS: '*literal*' equals 'literal in text'; fail-closed on other wildcards.
IS NOT: general glob.
"""
import ast
import sys
WC_22_VERSION = "wc-22.v1"

def match(pattern, text):
    """True when pattern is '*literal*' and the literal occurs in text."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    if len(pattern) < 2 or not pattern.startswith("*") or not pattern.endswith("*"):
        return False
    inner = pattern[1:-1]
    if "*" in inner or "?" in inner or "[" in inner:
        return False
    return inner in text

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
    assert match("*ell*", "hello")
    assert not match("*xyz*", "hello")
    assert match("**", "")
    assert not match("*a?*", "abc")
    assert match("*b*", "abc")
    assert stdlib_only()
    print("wc_22 OK")


if __name__ == "__main__":
    main()
