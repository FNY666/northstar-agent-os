"""wc_48: Basename glob

IS: matches the classic glob against the final path component.
IS NOT: directory-aware matching.
"""
import ast
import sys
WC_48_VERSION = "wc-48.v1"

def match(pattern, text):
    """True when the basename fully matches the glob pattern."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    base = text.rsplit("/", 1)[-1]

    def rec(p, t):
        if p == len(pattern):
            return t == len(base)
        if pattern[p] == "*":
            return rec(p + 1, t) or (t < len(base) and rec(p, t + 1))
        return t < len(base) and (pattern[p] == "?" or pattern[p] == base[t]) and rec(p + 1, t + 1)

    return rec(0, 0)

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
    assert match("*.py", "d/e/x.py")
    assert match("a?c", "d/abc")
    assert not match("*.py", "d/x.txt")
    assert match("*", "a/b/")
    assert not match("x", "d/y")
    assert stdlib_only()
    print("wc_48 OK")


if __name__ == "__main__":
    main()
