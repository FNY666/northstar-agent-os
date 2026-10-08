"""slide_33: Maximum number of vowels in a substring of length k.

Fixed-size window counting vowels: slide and adjust the count as characters enter and leave.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_33_VERSION = "slide-33.v1"


def max_vowels(s, k):
    """Maximum number of vowels in any substring of length k."""
    vowels = set("aeiou")
    n = len(s)
    if n == 0 or k <= 0:
        return 0
    if k > n:
        k = n
    window = sum(1 for ch in s[:k] if ch in vowels)
    best = window
    for i in range(k, n):
        if s[i] in vowels:
            window += 1
        if s[i - k] in vowels:
            window -= 1
        if window > best:
            best = window
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
    assert max_vowels("abciiidef", 3) == 3
    assert max_vowels("aeiou", 2) == 2
    assert max_vowels("leetcode", 3) == 2
    assert max_vowels("rhythms", 4) == 0
    assert max_vowels("a", 5) == 1
    assert stdlib_only()
    print("slide_33 OK")


if __name__ == "__main__":
    main()
