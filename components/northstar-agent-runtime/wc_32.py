"""wc_32: Step-budget glob (fail-closed)

IS: aborts with False after 'budget' backtracking steps.
IS NOT: a wall-clock timeout.
"""
import ast
import sys
WC_32_VERSION = "wc-32.v1"

def match(pattern, text, budget=100000):
    """True when the whole text matches within the step budget."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    if not isinstance(budget, int) or budget < 0:
        return False
    state = {"n": 0}

    def rec(p, t):
        state["n"] += 1
        if state["n"] > budget:
            return False
        if p == len(pattern):
            return t == len(text)
        if pattern[p] == "*":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
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
    assert not match("a*b", "axxb", budget=5)
    assert match("a*b", "axxb", budget=10)
    assert not match("a*b", "axxb", budget=-1)
    assert match("*", "abc")
    assert stdlib_only()
    print("wc_32 OK")


if __name__ == "__main__":
    main()
