"""dac-24: Merge intervals (divide and conquer).

Sort by start, merge each half, then merge the two merged halves. O(n log n).
"""
import ast
import sys

DAC_24_VERSION = "dac-24.v1"

def _merge_two(A, B):
    tmp = []
    i = j = 0
    while i < len(A) and j < len(B):
        if A[i][0] <= B[j][0]:
            tmp.append(A[i])
            i += 1
        else:
            tmp.append(B[j])
            j += 1
    tmp.extend(A[i:])
    tmp.extend(B[j:])
    out = []
    for s, e in tmp:
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def _mi(ivs):
    if len(ivs) <= 1:
        return list(ivs)
    mid = len(ivs) // 2
    return _merge_two(_mi(ivs[:mid]), _mi(ivs[mid:]))


def merge_intervals_dc(intervals):
    """Merge overlapping intervals via divide and conquer."""
    return _mi(sorted(intervals, key=lambda iv: iv[0]))

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
    assert merge_intervals_dc([]) == []
    assert merge_intervals_dc([(1, 3)]) == [(1, 3)]
    assert merge_intervals_dc([(1, 3), (2, 6), (8, 10), (15, 18)]) == [(1, 6), (8, 10), (15, 18)]
    assert merge_intervals_dc([(1, 4), (4, 5)]) == [(1, 5)]
    assert merge_intervals_dc([(5, 6), (1, 2)]) == [(1, 2), (5, 6)]
    assert stdlib_only()
    print("dac-24 OK")


if __name__ == "__main__":
    main()
