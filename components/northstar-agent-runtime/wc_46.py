"""wc_46: Path-component glob ('**' = whole components)

IS: '**' matches zero+ path components; '*'/'?' stay in one.
IS NOT: partial-component '**'.
"""
import ast
import sys
WC_46_VERSION = "wc-46.v1"

def _comp(pat, comp):
    def rec(p, t):
        if p == len(pat):
            return t == len(comp)
        if pat[p] == "*":
            return rec(p + 1, t) or (t < len(comp) and rec(p, t + 1))
        return t < len(comp) and (pat[p] == "?" or pat[p] == comp[t]) and rec(p + 1, t + 1)
    return rec(0, 0)


def match(pattern, text):
    """True when the path matches with component-level '**'."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    pparts = pattern.split("/")
    tparts = text.split("/")

    def rec(p, t):
        if p == len(pparts):
            return t == len(tparts)
        if pparts[p] == "**":
            return rec(p + 1, t) or (t < len(tparts) and rec(p, t + 1))
        return t < len(tparts) and _comp(pparts[p], tparts[t]) and rec(p + 1, t + 1)

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
    assert match("a/**/c", "a/b/d/c")
    assert match("*.py", "x.py")
    assert not match("*.py", "d/x.py")
    assert match("**/*.py", "d/e/x.py")
    assert not match("a/*/c", "a/b/d/c")
    assert match("**", "a/b")
    assert stdlib_only()
    print("wc_46 OK")


if __name__ == "__main__":
    main()
