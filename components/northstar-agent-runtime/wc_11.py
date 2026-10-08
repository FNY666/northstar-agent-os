"""wc_11: Glob via NFA simulation

IS: Thompson-style epsilon-closure simulation over pattern states.
IS NOT: classes or path semantics.
"""
import ast
import sys
WC_11_VERSION = "wc-11.v1"

def match(pattern, text):
    """True when the whole text matches, via NFA state simulation."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    m = len(pattern)

    def closure(states):
        stack = list(states)
        seen = set(states)
        while stack:
            s = stack.pop()
            if s < m and pattern[s] == "*" and s + 1 not in seen:
                seen.add(s + 1)
                stack.append(s + 1)
        return seen

    cur = closure({0})
    for ch in text:
        nxt = set()
        for s in cur:
            if s < m:
                if pattern[s] == "*":
                    nxt.add(s)
                elif pattern[s] == "?" or pattern[s] == ch:
                    nxt.add(s + 1)
        cur = closure(nxt)
        if not cur:
            return False
    return m in cur

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
    assert match("a?b", "axb")
    assert not match("a?b", "ab")
    assert match("*", "anything")
    assert match("", "")
    assert not match("a*b", "ba")
    assert stdlib_only()
    print("wc_11 OK")


if __name__ == "__main__":
    main()
