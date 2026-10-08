"""wc_38: Inverse glob (NOT match)

IS: True exactly when the classic glob does NOT fully match.
IS NOT: partial-match negation.
"""
import ast
import sys
WC_38_VERSION = "wc-38.v1"

def _wild(pat, text):
    def rec(p, t):
        if p == len(pat):
            return t == len(text)
        if pat[p] == "*":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        return t < len(text) and (pat[p] == "?" or pat[p] == text[t]) and rec(p + 1, t + 1)
    return rec(0, 0)


def match_not(pattern, text):
    """True when the pattern does NOT fully match the text."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    return not _wild(pattern, text)


def match(pattern, text):
    """Alias for the inverse match."""
    return match_not(pattern, text)

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
    assert match("a*", "bcd")
    assert not match("a*", "abc")
    assert match_not("a*", "xyz")
    assert not match_not("*", "anything")
    assert not match(1, "a")
    assert stdlib_only()
    print("wc_38 OK")


if __name__ == "__main__":
    main()
