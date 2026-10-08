"""wc_45: Token-based glob

IS: splits on a delimiter; '*' matches token runs, '?' one token.
IS NOT: character-level wildcards.
"""
import ast
import sys
WC_45_VERSION = "wc-45.v1"

def match(pattern, text, delim=" "):
    """True when the token sequence matches ('*' = token run)."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    if not isinstance(delim, str) or delim == "":
        return False
    ptoks = pattern.split(delim)
    ttoks = text.split(delim)

    def rec(p, t):
        if p == len(ptoks):
            return t == len(ttoks)
        if ptoks[p] == "*":
            return rec(p + 1, t) or (t < len(ttoks) and rec(p, t + 1))
        if t < len(ttoks) and (ptoks[p] == "?" or ptoks[p] == ttoks[t]):
            return rec(p + 1, t + 1)
        return False

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
    assert match("a * c", "a b c")
    assert match("* b", "a b")
    assert not match("a c", "a b c")
    assert match("a ? c", "a x c")
    assert match("a/*/c", "a/b/c", delim="/")
    assert not match("a", "a", delim="")
    assert stdlib_only()
    print("wc_45 OK")


if __name__ == "__main__":
    main()
