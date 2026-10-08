"""psum_13: Continuous Subarray Multiple of K

Track first index per remainder; a repeat 2+ apart means a valid multiple.

Time complexity: O(n) time
Space complexity: O(k)"""

import ast
import sys
PSUM_13_VERSION = "psum-13.v1"


def exists(a, k):
    seen = {0: -1}
    s = 0
    for i, x in enumerate(a):
        s += x
        m = s if k == 0 else s % k
        if m in seen:
            if i - seen[m] >= 2:
                return True
        else:
            seen[m] = i
    return False

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
    assert exists([23, 2, 4, 6, 7], 6) is True
    assert exists([23, 2, 6, 4, 7], 13) is False
    assert exists([0, 0], 0) is True
    assert exists([1, 2], 5) is False
    assert stdlib_only()
    print("psum_13 OK")


if __name__ == "__main__":
    main()
