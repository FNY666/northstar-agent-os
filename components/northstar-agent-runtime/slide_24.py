"""slide_24: Maximize the confusion of an exam.

Run the variable window twice (once per target answer): a window is valid when flips to the target do not exceed k.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_24_VERSION = "slide-24.v1"


def max_consec_answers(key, k):
    """Longest run achievable by flipping at most k answers."""
    best = 0
    for target in ("T", "F"):
        left = 0
        flips = 0
        for right, ch in enumerate(key):
            if ch != target:
                flips += 1
            while flips > k:
                if key[left] != target:
                    flips -= 1
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
    assert max_consec_answers("TTFF", 2) == 4
    assert max_consec_answers("TFFT", 1) == 3
    assert max_consec_answers("TTTTT", 2) == 5
    assert max_consec_answers("FFFFF", 0) == 5
    assert max_consec_answers("", 1) == 0
    assert stdlib_only()
    print("slide_24 OK")


if __name__ == "__main__":
    main()
