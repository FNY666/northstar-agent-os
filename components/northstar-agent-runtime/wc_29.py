"""wc_29: Whitespace-normalizing glob

IS: collapses whitespace runs on both sides, then classic match.
IS NOT: fuzzy or semantic text matching.
"""
import ast
import sys
WC_29_VERSION = "wc-29.v1"

def _norm(s):
    return " ".join(s.split())


def match(pattern, text):
    """True when normalized text matches the normalized pattern."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    pat = _norm(pattern)
    txt = _norm(text)

    def rec(p, t):
        if p == len(pat):
            return t == len(txt)
        if pat[p] == "*":
            return rec(p + 1, t) or (t < len(txt) and rec(p, t + 1))
        return t < len(txt) and (pat[p] == "?" or pat[p] == txt[t]) and rec(p + 1, t + 1)

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
    assert match("a b", "a   b")
    assert match("hello world", "hello\tworld")
    assert not match("a b", "ab")
    assert match("a*b", "a  x  b")
    assert not match("a  b", "ab")
    assert stdlib_only()
    print("wc_29 OK")


if __name__ == "__main__":
    main()
