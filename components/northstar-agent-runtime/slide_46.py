"""slide_46: Longest semi-repetitive substring.

Variable window allowing at most one adjacent equal pair: shrink the left edge whenever a second pair enters.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_46_VERSION = "slide-46.v1"


def longest_semi_repetitive(s):
    """Longest substring with at most one pair of adjacent equal digits."""
    n = len(s)
    if n <= 2:
        return n
    left = 0
    pairs = 0
    best = 1
    for right in range(1, n):
        if s[right] == s[right - 1]:
            pairs += 1
        while pairs > 1:
            left += 1
            if s[left] == s[left - 1]:
                pairs -= 1
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
    assert longest_semi_repetitive("52233") == 4
    assert longest_semi_repetitive("5494") == 4
    assert longest_semi_repetitive("1111111") == 2
    assert longest_semi_repetitive("1") == 1
    assert longest_semi_repetitive("12") == 2
    assert stdlib_only()
    print("slide_46 OK")


if __name__ == "__main__":
    main()
