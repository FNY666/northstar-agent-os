"""dac-36: Count smaller numbers after self.

Merge-sort divide and conquer that counts, for each element, how many right-side elements are smaller.
"""
import ast
import sys

DAC_36_VERSION = "dac-36.v1"

def count_smaller_dc(nums):
    """For each i, count of j>i with nums[j] < nums[i]."""
    n = len(nums)
    res = [0] * n
    idx = list(range(n))

    def sort_idx(lo, hi):
        if hi - lo <= 1:
            return
        mid = (lo + hi) // 2
        sort_idx(lo, mid)
        sort_idx(mid, hi)
        merged = []
        i, j = lo, mid
        right_count = 0
        while i < mid and j < hi:
            if nums[idx[j]] < nums[idx[i]]:
                merged.append(idx[j])
                right_count += 1
                j += 1
            else:
                res[idx[i]] += right_count
                merged.append(idx[i])
                i += 1
        while i < mid:
            res[idx[i]] += right_count
            merged.append(idx[i])
            i += 1
        while j < hi:
            merged.append(idx[j])
            j += 1
        idx[lo:hi] = merged

    sort_idx(0, n)
    return res

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
    assert count_smaller_dc([]) == []
    assert count_smaller_dc([5, 2, 6, 1]) == [2, 1, 1, 0]
    assert count_smaller_dc([1, 2, 3]) == [0, 0, 0]
    assert count_smaller_dc([3, 2, 1]) == [2, 1, 0]
    assert count_smaller_dc([1, 1, 1]) == [0, 0, 0]
    assert stdlib_only()
    print("dac-36 OK")


if __name__ == "__main__":
    main()
