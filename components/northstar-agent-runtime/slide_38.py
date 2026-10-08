"""slide_38: Take k of each character from left and right.

Complement window: minimize the taken prefix/suffix by maximizing the middle subarray that leaves at least k of each character outside.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_38_VERSION = "slide-38.v1"


def take_characters(s, k):
    """Min minutes taking chars from ends to get k of each a/b/c."""
    if k == 0:
        return 0
    total = {}
    for ch in s:
        total[ch] = total.get(ch, 0) + 1
    for ch in "abc":
        if total.get(ch, 0) < k:
            return -1
    limit = {ch: total.get(ch, 0) - k for ch in "abc"}
    window = {}
    left = 0
    best = 0
    for right, ch in enumerate(s):
        window[ch] = window.get(ch, 0) + 1
        while window.get(ch, 0) > limit.get(ch, 0):
            window[s[left]] -= 1
            left += 1
        if right - left + 1 > best:
            best = right - left + 1
    return len(s) - best

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
    assert take_characters("aabaaaacaabc", 2) == 8
    assert take_characters("a", 1) == -1
    assert take_characters("abc", 1) == 3
    assert take_characters("aaabbbccc", 2) == 7
    assert take_characters("abc", 0) == 0
    assert stdlib_only()
    print("slide_38 OK")


if __name__ == "__main__":
    main()
