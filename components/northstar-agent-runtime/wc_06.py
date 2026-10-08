"""wc_06: Glob with backslash escapes

IS: '\\' makes the next character literal ('\\*', '\\?', '\\\\').
IS NOT: character classes or extglob.
"""
import ast
import sys
WC_06_VERSION = "wc-06.v1"

def _tokenize(pattern):
    toks = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            toks.append(("lit", pattern[i + 1]))
            i += 2
        elif c == "*":
            toks.append(("star",))
            i += 1
        elif c == "?":
            toks.append(("any",))
            i += 1
        else:
            toks.append(("lit", c))
            i += 1
    return toks


def match(pattern, text):
    """True when the whole text matches with escapes honored."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    toks = _tokenize(pattern)

    def rec(p, t):
        if p == len(toks):
            return t == len(text)
        kind = toks[p][0]
        if kind == "star":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        if t >= len(text):
            return False
        if kind == "any":
            return rec(p + 1, t + 1)
        return toks[p][1] == text[t] and rec(p + 1, t + 1)

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
    assert match("a\\*b", "a*b")
    assert not match("a\\*b", "axxb")
    assert match("a\\?b", "a?b")
    assert match("a\\\\b", "a\\b")
    assert match("a*b", "axxb")
    assert stdlib_only()
    print("wc_06 OK")


if __name__ == "__main__":
    main()
