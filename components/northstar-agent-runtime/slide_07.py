"""slide_07: Minimum window substring.

Variable window with a need/deficit map: expand until every character of t is covered, then shrink from the left to minimize the window.

Time complexity: O(|s| + |t|) time
Space complexity: O(|s| + |t|) auxiliary
"""

import ast
import sys
SLIDE_07_VERSION = "slide-07.v1"


def min_window(s, t):
    """Smallest substring of s containing all chars of t (with multiplicity)."""
    if not s or not t:
        return ""
    need = {}
    for ch in t:
        need[ch] = need.get(ch, 0) + 1
    missing = len(t)
    left = 0
    best = (0, len(s) + 1)
    for right, ch in enumerate(s):
        if need.get(ch, 0) > 0:
            missing -= 1
        need[ch] = need.get(ch, 0) - 1
        while missing == 0:
            if right - left < best[1] - best[0]:
                best = (left, right + 1)
            need[s[left]] = need.get(s[left], 0) + 1
            if need[s[left]] > 0:
                missing += 1
            left += 1
    if best[1] - best[0] > len(s):
        return ""
    return s[best[0]:best[1]]

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
    assert min_window("ADOBECODEBANC", "ABC") == "BANC"
    assert min_window("a", "a") == "a"
    assert min_window("a", "aa") == ""
    assert min_window("ab", "b") == "b"
    assert min_window("abc", "d") == ""
    assert stdlib_only()
    print("slide_07 OK")


if __name__ == "__main__":
    main()
