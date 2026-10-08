"""slide_09: Find all anagrams in a string.

Fixed-size window with a frequency map: compare the window histogram against the pattern histogram at every position.

Time complexity: O(n) time
Space complexity: O(alphabet) auxiliary
"""

import ast
import sys
SLIDE_09_VERSION = "slide-09.v1"


def find_anagrams(s, p):
    """Start indices of p's anagrams in s."""
    m = len(p)
    n = len(s)
    if m == 0 or m > n:
        return []
    need = {}
    for ch in p:
        need[ch] = need.get(ch, 0) + 1
    window = {}
    out = []
    for i, ch in enumerate(s):
        window[ch] = window.get(ch, 0) + 1
        if i >= m:
            left_ch = s[i - m]
            window[left_ch] -= 1
            if window[left_ch] == 0:
                del window[left_ch]
        if window == need:
            out.append(i - m + 1)
    return out

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
    assert find_anagrams("cbaebabacd", "abc") == [0, 6]
    assert find_anagrams("abab", "ab") == [0, 1, 2]
    assert find_anagrams("a", "b") == []
    assert find_anagrams("aa", "aa") == [0]
    assert find_anagrams("abc", "abcd") == []
    assert stdlib_only()
    print("slide_09 OK")


if __name__ == "__main__":
    main()
