"""intv_28: Longest well-performing interval (well_performing).

Map tiring days to +1/-1; longest subarray with positive sum via first-seen prefix.

Time complexity: O(n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_28 = "intv-28.v1"


def well_performing(hours):
    """Longest interval where tiring days outnumber non-tiring days."""
    pref = 0
    first = {0: -1}
    best = 0
    for i, h in enumerate(hours):
        pref += 1 if h > 8 else -1
        if pref > 0:
            best = i + 1
        else:
            if pref - 1 in first:
                best = max(best, i - first[pref - 1])
            if pref not in first:
                first[pref] = i
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
    assert well_performing([9, 9, 6, 0, 6, 6, 9]) == 3
    assert well_performing([6, 6, 6]) == 0
    assert well_performing([9, 9, 9]) == 3
    assert well_performing([]) == 0
    assert well_performing([9, 6, 9, 6, 9]) == 5
    assert stdlib_only()
    print("intv_28 OK")


if __name__ == "__main__":
    main()
