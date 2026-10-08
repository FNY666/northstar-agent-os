"""wc_28: Strict glob (wildcards must consume)

IS: '*' must consume >= 1 char; '?' exactly one; full-string match.
IS NOT: empty-matching wildcards.
"""
import ast
import sys
WC_28_VERSION = "wc-28.v1"

def match(pattern, text):
    """True when the whole text matches and no wildcard matches empty."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False

    def rec(p, t):
        if p == len(pattern):
            return t == len(text)
        if pattern[p] == "*":
            return t < len(text) and (rec(p + 1, t + 1) or rec(p, t + 1))
        return t < len(text) and (pattern[p] == "?" or pattern[p] == text[t]) and rec(p + 1, t + 1)

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
    assert not match("a*b", "ab")
    assert match("a*b", "axb")
    assert not match("*", "")
    assert match("?", "x")
    assert not match("?", "")
    assert not match("a", 1)
    assert stdlib_only()
    print("wc_28 OK")


if __name__ == "__main__":
    main()
