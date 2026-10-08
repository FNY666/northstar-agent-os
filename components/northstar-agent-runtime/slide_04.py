"""slide_04: Longest ones after flipping at most k zeros.

Variable window over a binary string: expand right, and shrink left whenever more than k zeros are inside the window.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_04_VERSION = "slide-04.v1"


def longest_ones(s, k):
    """Longest run of 1s after flipping at most k zeros (s: str of 0/1)."""
    left = 0
    zeros = 0
    best = 0
    for right, ch in enumerate(s):
        if ch == "0":
            zeros += 1
        while zeros > k:
            if s[left] == "0":
                zeros -= 1
            left += 1
        if right - left + 1 > best:
            best = right - left + 1
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
    assert longest_ones("111001111", 1) == 5
    assert longest_ones("1101100111", 1) == 5
    assert longest_ones("0000", 2) == 2
    assert longest_ones("1111", 0) == 4
    assert longest_ones("", 3) == 0
    assert longest_ones("010101", 2) == 5
    assert stdlib_only()
    print("slide_04 OK")


if __name__ == "__main__":
    main()
