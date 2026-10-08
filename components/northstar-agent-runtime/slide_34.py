"""slide_34: Defuse the bomb.

Circular sliding window: each position is replaced by the sum of the next k (or previous |k|) elements, wrapping around.

Time complexity: O(n) time
Space complexity: O(n) output
"""

import ast
import sys
SLIDE_34_VERSION = "slide-34.v1"


def decrypt(code, k):
    """Defuse the bomb: circular sliding window sums."""
    n = len(code)
    if n == 0:
        return []
    if k == 0:
        return [0] * n
    out = [0] * n
    if k > 0:
        window = sum(code[1:k + 1])
        for i in range(n):
            out[i] = window
            window += code[(i + k + 1) % n] - code[(i + 1) % n]
    else:
        window = sum(code[k:])
        for i in range(n):
            out[i] = window
            window += code[i % n] - code[(i + k) % n]
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
    assert decrypt([5, 7, 1, 4], 3) == [12, 10, 16, 13]
    assert decrypt([1, 2, 3, 4], 0) == [0, 0, 0, 0]
    assert decrypt([2, 4, 9, 3], -2) == [12, 5, 6, 13]
    assert decrypt([1], 1) == [0]
    assert decrypt([], 2) == []
    assert stdlib_only()
    print("slide_34 OK")


if __name__ == "__main__":
    main()
