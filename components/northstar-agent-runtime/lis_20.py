"""lis-20: Longest string chain.

DP over predecessors formed by deleting one character.

Time complexity: O(n * L^2) time
Space complexity: O(n * L)"""

import ast
import sys
LIS_20_VERSION = "lis-20.v1"


def _check_words(words):
    """Validate words is a list/tuple of strings."""
    if not isinstance(words, (list, tuple)):
        raise ValueError("words must be a list or tuple")
    for w in words:
        if not isinstance(w, str):
            raise ValueError("words must be strings")
    return list(words)
def longest_string_chain(words):
    """Longest chain where each word is a predecessor of the next."""
    ws = _check_words(words)
    ordered = sorted(set(ws), key=len)
    dp = {}
    best = 0
    for w in ordered:
        cur = 1
        for i in range(len(w)):
            pred = w[:i] + w[i + 1:]
            if pred in dp and dp[pred] + 1 > cur:
                cur = dp[pred] + 1
        dp[w] = cur
        if cur > best:
            best = cur
    return best

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
    assert longest_string_chain(["a", "b", "ba", "bca", "bda", "bdca"]) == 4
    assert longest_string_chain([]) == 0
    assert longest_string_chain(["a"]) == 1
    assert stdlib_only()
    print("lis-20 OK")


if __name__ == "__main__":
    main()
