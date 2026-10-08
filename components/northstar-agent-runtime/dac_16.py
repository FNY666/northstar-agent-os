"""dac-16: Skyline problem.

Split buildings in half, solve each silhouette, merge by sweeping x. O(n log n).
"""
import ast
import sys

DAC_16_VERSION = "dac-16.v1"

def _merge_skylines(left, right):
    i = j = 0
    h1 = h2 = 0
    out = []

    def append(x, h):
        if out and out[-1][1] == h:
            return
        if out and out[-1][0] == x:
            out[-1] = (x, h)
            return
        out.append((x, h))

    while i < len(left) and j < len(right):
        if left[i][0] < right[j][0]:
            x, h1 = left[i]
            i += 1
        elif left[i][0] > right[j][0]:
            x, h2 = right[j]
            j += 1
        else:
            x = left[i][0]
            h1 = left[i][1]
            h2 = right[j][1]
            i += 1
            j += 1
        append(x, max(h1, h2))
    while i < len(left):
        x, h1 = left[i]
        i += 1
        append(x, max(h1, h2))
    while j < len(right):
        x, h2 = right[j]
        j += 1
        append(x, max(h1, h2))
    return out


def _skyline(buildings):
    if not buildings:
        return []
    if len(buildings) == 1:
        l, r, h = buildings[0]
        return [(l, h), (r, 0)]
    mid = len(buildings) // 2
    return _merge_skylines(_skyline(buildings[:mid]), _skyline(buildings[mid:]))


def skyline(buildings):
    """Skyline silhouette via divide and conquer; returns list of (x, height)."""
    return _skyline(sorted(buildings, key=lambda b: b[0]))

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
    assert skyline([]) == []
    assert skyline([(1, 5, 3)]) == [(1, 3), (5, 0)]
    assert skyline([(1, 5, 3), (2, 4, 4)]) == [(1, 3), (2, 4), (4, 3), (5, 0)]
    assert skyline([(0, 2, 2), (2, 4, 2)]) == [(0, 2), (4, 0)]
    assert stdlib_only()
    print("dac-16 OK")


if __name__ == "__main__":
    main()
