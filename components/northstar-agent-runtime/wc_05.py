"""wc_05: Glob with negated-only classes

IS: '[!...]' negated sets; any other '[' is a literal character.
IS NOT: ranges, positive classes, or brace expansion.
"""
import ast
import sys
WC_05_VERSION = "wc-05.v1"

def _tokenize(pattern):
    toks = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            toks.append(("star",))
            i += 1
        elif c == "?":
            toks.append(("any",))
            i += 1
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j != -1 and pattern[i + 1:j][:1] == "!":
                toks.append(("nclass", frozenset(pattern[i + 2:j])))
                i = j + 1
            else:
                toks.append(("lit", c))
                i += 1
        else:
            toks.append(("lit", c))
            i += 1
    return toks


def match(pattern, text):
    """True when the whole text matches; only '[!...]' is special."""
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
        if kind == "lit":
            return toks[p][1] == text[t] and rec(p + 1, t + 1)
        return text[t] not in toks[p][1] and rec(p + 1, t + 1)

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
    assert match("a[!b]c", "axc")
    assert not match("a[!b]c", "abc")
    assert match("a[bc]d", "a[bc]d")
    assert not match("a[bc]d", "abd")
    assert match("a*b", "axxb")
    assert stdlib_only()
    print("wc_05 OK")


if __name__ == "__main__":
    main()
