"""wc_07: Star-only wildcard

IS: only '*' is special; '?', '[', and others are literal.
IS NOT: single-char wildcards or classes.
"""
import ast
import sys
WC_07_VERSION = "wc-07.v1"

def match(pattern, text):
    """True when the whole text matches with only '*' wildcard."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False

    def rec(p, t):
        if p == len(pattern):
            return t == len(text)
        if pattern[p] == "*":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        return t < len(text) and pattern[p] == text[t] and rec(p + 1, t + 1)

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
    assert match("a*b", "axxxb")
    assert not match("a?b", "axb")
    assert match("a?b", "a?b")
    assert match("*end", "the end")
    assert match("*", "")
    assert stdlib_only()
    print("wc_07 OK")


if __name__ == "__main__":
    main()
