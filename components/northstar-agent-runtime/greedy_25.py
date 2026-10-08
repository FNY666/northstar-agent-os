"""greedy_25: Queue reconstruction by height.

Insert tallest first; each person goes exactly at index k among already placed taller people.

Time complexity: O(n^2) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_25_VERSION = "greedy-25.v1"


def reconstruct_queue(people):
    """Rebuild the queue from [height, k] pairs."""
    ordered = sorted(people, key=lambda p: (-p[0], p[1]))
    res = []
    for h, k in ordered:
        res.insert(k, [h, k])
    return res

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
    assert reconstruct_queue([[7, 0], [4, 4], [7, 1], [5, 0], [6, 1], [5, 2]]) == [[5, 0], [7, 0], [5, 2], [6, 1], [4, 4], [7, 1]]
    assert reconstruct_queue([]) == []
    assert reconstruct_queue([[6, 0]]) == [[6, 0]]
    assert reconstruct_queue([[6, 0], [5, 0], [4, 0], [3, 2], [2, 2], [1, 4]]) == [[4, 0], [5, 0], [2, 2], [3, 2], [1, 4], [6, 0]]
    assert stdlib_only()
    print("greedy_25 OK")


if __name__ == "__main__":
    main()
