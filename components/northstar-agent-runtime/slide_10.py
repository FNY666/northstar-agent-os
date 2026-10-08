"""slide_10: Longest repeating character replacement.

Variable window: a window is valid when its length minus the count of its most frequent char does not exceed k replacements.

Time complexity: O(n) time
Space complexity: O(alphabet) auxiliary
"""

import ast
import sys
SLIDE_10_VERSION = "slide-10.v1"


def char_replacement(s, k):
    """Longest substring achievable by replacing at most k characters."""
    counts = {}
    left = 0
    best = 0
    for right, ch in enumerate(s):
        counts[ch] = counts.get(ch, 0) + 1
        while (right - left + 1) - max(counts.values()) > k:
            counts[s[left]] -= 1
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
    assert char_replacement("ABAB", 2) == 4
    assert char_replacement("AABABBA", 1) == 4
    assert char_replacement("AAAA", 0) == 4
    assert char_replacement("ABCDE", 1) == 2
    assert char_replacement("", 2) == 0
    assert stdlib_only()
    print("slide_10 OK")


if __name__ == "__main__":
    main()
