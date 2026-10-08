"""wc_41: Named-capture glob ('{name}')

IS: '{name}' acts as '*' and capture_named() returns a dict.
IS NOT: brace expansion or regex groups.
"""
import ast
import sys
WC_41_VERSION = "wc-41.v1"

def _tokenize(pattern):
    toks = []
    i, n = 0, len(pattern)
    while i < n:
        if pattern[i] == "{":
            j = pattern.find("}", i + 1)
            if j == -1:
                toks.append(("lit", pattern[i:]))
                break
            name = pattern[i + 1:j]
            if not name.isidentifier():
                return None
            toks.append(("named", name))
            i = j + 1
        else:
            j = pattern.find("{", i)
            if j == -1:
                j = n
            toks.append(("lit", pattern[i:j]))
            i = j
    return toks


def capture_named(pattern, text):
    """Dict of '{name}' captures, or None when there is no full match."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return None
    toks = _tokenize(pattern)
    if toks is None:
        return None
    out = {}

    def rec(p, t):
        if p == len(toks):
            return t == len(text)
        kind, val = toks[p]
        if kind == "lit":
            return text.startswith(val, t) and rec(p + 1, t + len(val))
        for end in range(t, len(text) + 1):
            out[val] = text[t:end]
            if rec(p + 1, end):
                return True
        out.pop(val, None)
        return False

    return dict(out) if rec(0, 0) else None


def match(pattern, text):
    """True when the pattern fully matches."""
    return capture_named(pattern, text) is not None

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
    assert capture_named("{u}@{h}", "bob@x.com") == {"u": "bob", "h": "x.com"}
    assert capture_named("a{n}b", "axxb") == {"n": "xx"}
    assert capture_named("{a}{b}", "xy") == {"a": "", "b": "xy"}
    assert capture_named("{u}", 123) is None
    assert not match("{9bad}", "x")
    assert match("{u}", "anything")
    assert stdlib_only()
    print("wc_41 OK")


if __name__ == "__main__":
    main()
