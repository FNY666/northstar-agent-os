"""intv_23: Total poisoned duration from attacks (teemo_poison).

Each attack poisons [t, t+duration); merge consecutive overlaps.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

INTV_23 = "intv-23.v1"


def teemo_poison(time_series, duration):
    """Total seconds Ashe stays poisoned."""
    if not time_series or duration <= 0:
        return 0
    total = 0
    for i in range(len(time_series) - 1):
        total += min(duration, time_series[i + 1] - time_series[i])
    return total + duration

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
    assert teemo_poison([1, 4], 2) == 4
    assert teemo_poison([1, 2], 2) == 3
    assert teemo_poison([1, 2, 3, 4, 5], 5) == 9
    assert teemo_poison([], 3) == 0
    assert teemo_poison([1], 1) == 1
    assert stdlib_only()
    print("intv_23 OK")


if __name__ == "__main__":
    main()
