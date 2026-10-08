"""slide_20: Maximum points from cards.

Take k cards from either end: equivalently minimize the contiguous middle window of length n - k.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_20_VERSION = "slide-20.v1"


def max_score_cards(cards, k):
    """Max sum taking exactly k cards from either end."""
    n = len(cards)
    if k >= n:
        return sum(cards)
    if k <= 0:
        return 0
    window = sum(cards[:n - k])
    total = sum(cards)
    best = total - window
    for i in range(n - k, n):
        window += cards[i] - cards[i - (n - k)]
        cand = total - window
        if cand > best:
            best = cand
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
    assert max_score_cards([1, 2, 3, 4, 5, 6, 1], 3) == 12
    assert max_score_cards([2, 2, 2], 2) == 4
    assert max_score_cards([9, 7, 7, 9, 7, 7, 9], 7) == 55
    assert max_score_cards([1, 1000, 1], 1) == 1
    assert max_score_cards([100, 40, 17, 9, 73, 75], 3) == 248
    assert stdlib_only()
    print("slide_20 OK")


if __name__ == "__main__":
    main()
