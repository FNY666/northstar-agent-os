"""wc_24: Glob with star collapsing

IS: runs of '*' collapse to one before classic '?'/'*' matching.
IS NOT: path semantics or classes.
"""
import ast
import sys
WC_24_VERSION = "wc-24.v1"

def _collapse(pattern):
    out = []
    for ch in pattern:
        if ch == "*" and out and out[-1] == "*":
            continue
        out.append(ch)
    return "".join(out)


def match(pattern, text):
    """True when the whole text matches after collapsing '*' runs."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    pat = _collapse(pattern)

    def rec(p, t):
        if p == len(pat):
            return t == len(text)
        if pat[p] == "*":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        return t < len(text) and (pat[p] == "?" or pat[p] == text[t]) and rec(p + 1, t + 1)

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
    assert match("a**b", "axxb")
    assert match("***", "abc")
    assert match("a***?b", "axyb")
    assert not match("a**b", "abX")
    assert match("**a**", "xa")
    assert stdlib_only()
    print("wc_24 OK")


if __name__ == "__main__":
    main()
