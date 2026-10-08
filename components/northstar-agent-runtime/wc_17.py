"""wc_17: Extglob '?(...)' (zero or one)

IS: '?(a|b)' matches zero or one alternative, plus '?'/'*'.
IS NOT: other extglob operators or nesting.
"""
import ast
import sys
WC_17_VERSION = "wc-17.v1"

def _tokenize(pattern):
    toks = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*" and not (i + 1 < n and pattern[i + 1] == "("):
            toks.append(("star",))
            i += 1
        elif c == "?" and not (i + 1 < n and pattern[i + 1] == "("):
            toks.append(("any",))
            i += 1
        elif c in "*?" and i + 1 < n and pattern[i + 1] == "(":
            j = pattern.find(")", i + 2)
            if j == -1:
                toks.append(("lit", c))
                i += 1
            else:
                toks.append(("maybeof", pattern[i + 2:j].split("|")))
                i = j + 1
        else:
            toks.append(("lit", c))
            i += 1
    return toks


def match(pattern, text):
    """True when the whole text matches with '?(...)' honored."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    toks = _tokenize(pattern)

    def rec(p, t):
        if p == len(toks):
            return t == len(text)
        kind = toks[p][0]
        if kind == "star":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        if kind == "any":
            return t < len(text) and rec(p + 1, t + 1)
        if kind == "lit":
            return t < len(text) and toks[p][1] == text[t] and rec(p + 1, t + 1)
        if rec(p + 1, t):
            return True
        for alt in toks[p][1]:
            if text.startswith(alt, t) and rec(p + 1, t + len(alt)):
                return True
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
    assert match("?(a|b)c", "c")
    assert match("?(a|b)c", "ac")
    assert not match("?(a|b)c", "abc")
    assert not match("?(a|b)c", "bcx")
    assert match("?(ab|cd)", "")
    assert stdlib_only()
    print("wc_17 OK")


if __name__ == "__main__":
    main()
