"""wc_26: Glob where '?' matches word chars only

IS: '?' matches [A-Za-z0-9_] only; '*' matches anything.
IS NOT: locale word definitions.
"""
import ast
import sys
WC_26_VERSION = "wc-26.v1"

def _is_word(ch):
    return ch == "_" or ch.isalnum()


def match(pattern, text):
    """True when the whole text matches with word-only '?'."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False

    def rec(p, t):
        if p == len(pattern):
            return t == len(text)
        if pattern[p] == "*":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        if pattern[p] == "?":
            return t < len(text) and _is_word(text[t]) and rec(p + 1, t + 1)
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
    assert match("a?c", "abc")
    assert not match("a?c", "a-c")
    assert match("a?c", "a_c")
    assert match("a*b", "a-b")
    assert not match("a?c", "a c")
    assert stdlib_only()
    print("wc_26 OK")


if __name__ == "__main__":
    main()
