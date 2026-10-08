"""dac-25: Longest common prefix.

Split the string list in half, solve each half, combine with pairwise LCP.
"""
import ast
import sys

DAC_25_VERSION = "dac-25.v1"

def _lcp2(a, b):
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return a[:i]


def _lcp(strs, lo, hi):
    if lo == hi:
        return strs[lo]
    mid = (lo + hi) // 2
    return _lcp2(_lcp(strs, lo, mid), _lcp(strs, mid + 1, hi))


def longest_common_prefix(strs):
    """Longest common prefix via divide and conquer."""
    if not strs:
        return ""
    return _lcp(list(strs), 0, len(strs) - 1)

def stdlib_only() -> bool:
    # Parse this file with ast; every import must be a used stdlib module.
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
    assert longest_common_prefix([]) == ""
    assert longest_common_prefix(["flower"]) == "flower"
    assert longest_common_prefix(["flower", "flow", "flight"]) == "fl"
    assert longest_common_prefix(["dog", "racecar", "car"]) == ""
    assert longest_common_prefix(["interspecies", "interstellar", "interstate"]) == "inters"
    assert stdlib_only()
    print("dac-25 OK")


if __name__ == "__main__":
    main()
