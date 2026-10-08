"""wc_36: Multi-pattern OR glob

IS: True when ANY pattern in the iterable fully matches.
IS NOT: alternation inside one pattern.
"""
import ast
import sys
WC_36_VERSION = "wc-36.v1"

def _wild(pat, text):
    def rec(p, t):
        if p == len(pat):
            return t == len(text)
        if pat[p] == "*":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        return t < len(text) and (pat[p] == "?" or pat[p] == text[t]) and rec(p + 1, t + 1)
    return rec(0, 0)


def match_any(patterns, text):
    """True when any pattern fully matches the text."""
    if not isinstance(text, str):
        return False
    try:
        pats = list(patterns)
    except TypeError:
        return False
    return any(isinstance(p, str) and _wild(p, text) for p in pats)


def match(pattern, text):
    """Single-pattern convenience wrapper."""
    return match_any([pattern], text)

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
    assert match_any(["a*", "b*"], "bxyz")
    assert not match_any(["a*", "b*"], "cxyz")
    assert not match_any([], "a")
    assert match("a*", "abc")
    assert not match_any([123], "a")
    assert not match_any(["a*"], 1)
    assert stdlib_only()
    print("wc_36 OK")


if __name__ == "__main__":
    main()
