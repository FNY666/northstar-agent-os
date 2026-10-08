"""wc_43: Anchored match vs unanchored search

IS: match() is full-string; search() tries every start offset.
IS NOT: span reporting.
"""
import ast
import sys
WC_43_VERSION = "wc-43.v1"

def match(pattern, text):
    """True when the whole text matches."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False

    def rec(p, t):
        if p == len(pattern):
            return t == len(text)
        if pattern[p] == "*":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        return t < len(text) and (pattern[p] == "?" or pattern[p] == text[t]) and rec(p + 1, t + 1)

    return rec(0, 0)


def search(pattern, text):
    """True when the pattern fully matches some suffix-starting slice."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    return any(match(pattern, text[i:]) for i in range(len(text) + 1))

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
    assert not match("b*", "ab")
    assert search("b*", "ab")
    assert match("a*", "ab")
    assert not search("z*", "abc")
    assert search("*", "")
    assert not search("a", 1)
    assert stdlib_only()
    print("wc_43 OK")


if __name__ == "__main__":
    main()
