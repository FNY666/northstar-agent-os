"""wc_09: Glob via dynamic-programming table

IS: O(m*n) table-based '?'/'*' matcher, no recursion depth risk.
IS NOT: classes or path semantics.
"""
import ast
import sys
WC_09_VERSION = "wc-09.v1"

def match(pattern, text):
    """True when the whole text matches, computed with a DP table."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    m, n = len(pattern), len(text)
    dp = [[False] * (n + 1) for _ in range(m + 1)]
    dp[0][0] = True
    for i in range(1, m + 1):
        if pattern[i - 1] == "*":
            dp[i][0] = dp[i - 1][0]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            c = pattern[i - 1]
            if c == "*":
                dp[i][j] = dp[i - 1][j] or dp[i][j - 1]
            elif c == "?" or c == text[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
    return dp[m][n]

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
    assert match("*", "")
    assert match("", "")
    assert not match("", "a")
    assert match("a*b*c", "aXXbYYc")
    assert stdlib_only()
    print("wc_09 OK")


if __name__ == "__main__":
    main()
