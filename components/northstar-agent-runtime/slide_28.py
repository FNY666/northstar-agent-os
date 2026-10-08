"""slide_28: Longest substring with each character at least k times.

Iterate over possible distinct-character budgets; for each budget a sliding window keeps the best valid segment.

Time complexity: O(n * alphabet) time
Space complexity: O(alphabet) auxiliary
"""

import ast
import sys
SLIDE_28_VERSION = "slide-28.v1"


def longest_substring_k_repeat(s, k):
    """Longest substring where each char appears at least k times."""
    if k <= 1:
        return len(s)
    best = 0
    max_distinct = len(set(s))
    for target in range(1, max_distinct + 1):
        counts = {}
        left = 0
        for right, ch in enumerate(s):
            counts[ch] = counts.get(ch, 0) + 1
            while len(counts) > target:
                counts[s[left]] -= 1
                if counts[s[left]] == 0:
                    del counts[s[left]]
                left += 1
            if len(counts) == target and all(c >= k for c in counts.values()):
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
    assert longest_substring_k_repeat("aaabb", 3) == 3
    assert longest_substring_k_repeat("ababbc", 2) == 5
    assert longest_substring_k_repeat("a", 1) == 1
    assert longest_substring_k_repeat("abc", 2) == 0
    assert longest_substring_k_repeat("aaabbb", 3) == 6
    assert stdlib_only()
    print("slide_28 OK")


if __name__ == "__main__":
    main()
