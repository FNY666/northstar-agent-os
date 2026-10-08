"""wc_02: Path-aware glob ('**' crosses '/')

IS: '*' and '?' never cross '/'; '**' matches across separators.
IS NOT: character classes, brace expansion, or case folding.
"""
import ast
import sys
WC_02_VERSION = "wc-02.v1"

def _tokenize(pattern):
    toks = []
    i, n = 0, len(pattern)
    while i < n:
        if pattern[i] == "*" and i + 1 < n and pattern[i + 1] == "*":
            toks.append("**")
            i += 2
        else:
            toks.append(pattern[i])
            i += 1
    return toks


def match(pattern, text):
    """True when the whole path matches; '*'/'?' stay inside one segment."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    toks = _tokenize(pattern)

    def rec(p, t):
        if p == len(toks):
            return t == len(text)
        tok = toks[p]
        if tok == "**":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        if tok == "*":
            if rec(p + 1, t):
                return True
            return t < len(text) and text[t] != "/" and rec(p, t + 1)
        if t < len(text):
            if tok == "?":
                return text[t] != "/" and rec(p + 1, t + 1)
            return tok == text[t] and rec(p + 1, t + 1)
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
    assert match("*.py", "a.py")
    assert not match("*.py", "d/a.py")
    assert match("**/*.py", "d/a.py")
    assert match("a/**/b", "a/x/y/b")
    assert not match("a?c", "a/c")
    assert match("**", "a/b/c")
    assert stdlib_only()
    print("wc_02 OK")


if __name__ == "__main__":
    main()
