"""wc_10: Glob via greedy two-pointer scan

IS: linear-time '?'/'*' matcher with star backtracking pointers.
IS NOT: classes or path semantics.
"""
import ast
import sys
WC_10_VERSION = "wc-10.v1"

def match(pattern, text):
    """True when the whole text matches, in O(len) time."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    px, tx = 0, 0
    star, ss = -1, 0
    while tx < len(text):
        if px < len(pattern) and (pattern[px] == "?" or pattern[px] == text[tx]):
            px += 1
            tx += 1
        elif px < len(pattern) and pattern[px] == "*":
            star = px
            px += 1
            ss = tx
        elif star != -1:
            px = star + 1
            ss += 1
            tx = ss
        else:
            return False
    while px < len(pattern) and pattern[px] == "*":
        px += 1
    return px == len(pattern)

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
    assert match("*a*b*", "xxaxxbxx")
    assert not match("a*b", "ba")
    assert match("", "")
    assert stdlib_only()
    print("wc_10 OK")


if __name__ == "__main__":
    main()
