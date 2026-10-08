"""lis-48: Online streaming LIS.

Append-only patience structure with O(1) length queries.

Time complexity: O(log n) amortized per append
Space complexity: O(n)"""

import ast
import bisect
import sys
LIS_48_VERSION = "lis-48.v1"



class OnlineLIS:
    """Streaming LIS length estimator: append values, query length."""

    def __init__(self):
        self._tails = []

    def append(self, x):
        """Feed one value into the stream."""
        if not isinstance(x, (int, float)):
            raise ValueError("values must be numbers")
        i = bisect.bisect_left(self._tails, x)
        if i == len(self._tails):
            self._tails.append(x)
        else:
            self._tails[i] = x

    def length(self):
        """Current LIS length of everything appended so far."""
        return len(self._tails)

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
    o = OnlineLIS()
    o.append(3); o.append(1); o.append(2)
    assert o.length() == 2
    assert OnlineLIS().length() == 0
    assert stdlib_only()
    print("lis-48 OK")


if __name__ == "__main__":
    main()
