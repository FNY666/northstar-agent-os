"""dac-47: Jump search.

Jump ahead by sqrt(n) blocks to bracket the target, then scan linearly. O(sqrt(n)).
"""
import ast
import sys

DAC_47_VERSION = "dac-47.v1"

def jump_search(a, x):
    """Jump search on a sorted list; index of *x* or -1."""
    n = len(a)
    if n == 0:
        return -1
    step0 = int(n ** 0.5) or 1
    step = step0
    prev = 0
    while a[min(step, n) - 1] < x:
        prev = step
        step += step0
        if prev >= n:
            return -1
    while prev < min(step, n) and a[prev] < x:
        prev += 1
    if prev < n and a[prev] == x:
        return prev
    return -1

def stdlib_only() -> bool:
    # Parse this file with ast; every import must be a used stdlib module.
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
    assert jump_search([], 1) == -1
    assert jump_search([1, 3, 5, 7, 9], 7) == 3
    assert jump_search([1, 3, 5, 7, 9], 1) == 0
    assert jump_search([1, 3, 5, 7, 9], 9) == 4
    assert jump_search([1, 3, 5, 7, 9], 6) == -1
    assert jump_search(list(range(0, 200, 2)), 100) == 50
    assert stdlib_only()
    print("dac-47 OK")


if __name__ == "__main__":
    main()
