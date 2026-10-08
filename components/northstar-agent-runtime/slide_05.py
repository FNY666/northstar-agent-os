"""slide_05: Longest substring without repeating characters.

Variable window with a last-seen index map: jump the left edge past the previous occurrence whenever a duplicate enters the window.

Time complexity: O(n) time
Space complexity: O(min(n, alphabet)) auxiliary
"""

import ast
import sys
SLIDE_05_VERSION = "slide-05.v1"


def longest_unique(s):
    """Length of the longest substring without repeating characters."""
    seen = {}
    left = 0
    best = 0
    for right, ch in enumerate(s):
        if ch in seen and seen[ch] >= left:
            left = seen[ch] + 1
        seen[ch] = right
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
    assert longest_unique("abcabcbb") == 3
    assert longest_unique("bbbbb") == 1
    assert longest_unique("") == 0
    assert longest_unique("pwwkew") == 3
    assert longest_unique("abcdef") == 6
    assert stdlib_only()
    print("slide_05 OK")


if __name__ == "__main__":
    main()
