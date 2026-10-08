"""greedy_42: Greedy set cover.

Repeatedly pick the subset covering the most still-uncovered elements (ln n approximation).

Time complexity: O(m * n * k) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_42_VERSION = "greedy-42.v1"


def greedy_set_cover(universe, subsets):
    """Return the indices of subsets chosen by the greedy cover."""
    uncovered = set(universe)
    chosen = []
    used = [False] * len(subsets)
    while uncovered:
        best = -1
        best_gain = 0
        for i, s in enumerate(subsets):
            if used[i]:
                continue
            gain = len(uncovered & set(s))
            if gain > best_gain:
                best_gain = gain
                best = i
        if best == -1:
            break
        used[best] = True
        chosen.append(best)
        uncovered -= set(subsets[best])
    return chosen

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
    assert greedy_set_cover({1, 2, 3, 4, 5}, [{1, 2, 3}, {2, 4}, {3, 4}, {4, 5}]) == [0, 3]
    assert greedy_set_cover(set(), [{1}]) == []
    assert greedy_set_cover({1}, [{1}]) == [0]
    c = greedy_set_cover({1, 2, 3}, [{1}, {2}, {3}, {1, 2, 3}])
    assert c == [3]
    assert stdlib_only()
    print("greedy_42 OK")


if __name__ == "__main__":
    main()
