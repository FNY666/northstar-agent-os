"""wc_49: Guarded glob (length + budget + dotfile)

IS: combines max length, step budget, and dotfile rule, fail-closed.
IS NOT: a wall-clock timeout.
"""
import ast
import sys
WC_49_VERSION = "wc-49.v1"

def match(pattern, text, max_len=4096, budget=100000):
    """True when the whole text matches under all three guards."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    if len(pattern) > max_len or len(text) > max_len:
        return False
    if not isinstance(budget, int) or budget < 0:
        return False
    steps = {"n": 0}

    def rec(p, t):
        steps["n"] += 1
        if steps["n"] > budget:
            return False
        if p == len(pattern):
            return t == len(text)
        if pattern[p] == "*":
            if rec(p + 1, t):
                return True
            if t < len(text) and not (p == 0 and t == 0 and text.startswith(".")):
                return rec(p, t + 1)
            return False
        return t < len(text) and (pattern[p] == "?" or pattern[p] == text[t]) and rec(p + 1, t + 1)

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
    assert match("a*b", "axxb")
    assert not match("*", ".hidden")
    assert not match("a*", "x" * 5000)
    assert not match("a*b", "axxb", budget=3)
    assert match("a*b", "axxb")
    assert not match(".*", "x", max_len=1)
    assert stdlib_only()
    print("wc_49 OK")


if __name__ == "__main__":
    main()
