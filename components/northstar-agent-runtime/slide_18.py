"""slide_18: Count occurrences of anagrams.

Fixed-size window with a frequency map: count every window whose histogram matches the pattern histogram.

Time complexity: O(n) time
Space complexity: O(alphabet) auxiliary
"""

import ast
import sys
SLIDE_18_VERSION = "slide-18.v1"


def count_anagrams(s, p):
    """Number of windows of s that are anagrams of p."""
    m = len(p)
    n = len(s)
    if m == 0 or m > n:
        return 0
    need = {}
    for ch in p:
        need[ch] = need.get(ch, 0) + 1
    window = {}
    count = 0
    for i, ch in enumerate(s):
        window[ch] = window.get(ch, 0) + 1
        if i >= m:
            lc = s[i - m]
            window[lc] -= 1
            if window[lc] == 0:
                del window[lc]
        if window == need:
            count += 1
    return count

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
    assert count_anagrams("cbaebabacd", "abc") == 2
    assert count_anagrams("abab", "ab") == 3
    assert count_anagrams("a", "b") == 0
    assert count_anagrams("aaaa", "aa") == 3
    assert count_anagrams("abc", "") == 0
    assert stdlib_only()
    print("slide_18 OK")


if __name__ == "__main__":
    main()
