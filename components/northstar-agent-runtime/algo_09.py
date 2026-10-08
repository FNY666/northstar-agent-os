"""Bucket sort: distribute into buckets, sort each bucket, concatenate.

Floats must lie in [0, 1) and are bucketed directly by value. Integers of
any range are first normalized to [0, 1] via min-max scaling. Each bucket
is sorted with insertion sort, then buckets are concatenated in order.

Time complexity: O(n + k) average for uniform input (k = bucket count),
O(n^2) worst when everything lands in one bucket.
Space complexity: O(n).
"""

import ast
import sys
from typing import List

ALGO_09_VERSION = "algo-09.v1"


def bucket_sort(arr: List[float]) -> List[float]:
    """Return a NEW list sorted ascending.

    Accepts floats in [0, 1) or ints of any range (normalized internally).
    """
    a = list(arr)
    n = len(a)
    if n < 2:
        return a
    if all(isinstance(v, int) and not isinstance(v, bool) for v in a):
        lo = min(a)
        hi = max(a)
        if lo == hi:
            return a
        span = hi - lo
        keys = [(v - lo) / span for v in a]  # normalized into [0, 1]
    else:
        for v in a:
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ValueError("bucket_sort needs floats in [0, 1) or ints, got %r" % (v,))
            if not 0 <= v < 1:
                raise ValueError("bucket_sort floats must lie in [0, 1), got %r" % (v,))
        keys = [float(v) for v in a]
    buckets: List[List[float]] = [[] for _ in range(n)]
    for key, value in zip(keys, a):
        idx = min(int(key * n), n - 1)
        buckets[idx].append(value)
    out: List[float] = []
    for bucket in buckets:
        for i in range(1, len(bucket)):
            keyv = bucket[i]
            j = i - 1
            while j >= 0 and bucket[j] > keyv:
                bucket[j + 1] = bucket[j]
                j -= 1
            bucket[j + 1] = keyv
        out.extend(bucket)
    return out


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
    assert bucket_sort([0.42, 0.13, 0.87, 0.02, 0.55]) == [0.02, 0.13, 0.42, 0.55, 0.87]
    assert bucket_sort([5, 3, 1, 4, 2]) == [1, 2, 3, 4, 5]
    assert bucket_sort([-10, 7, 0, -3]) == [-10, -3, 0, 7]
    assert bucket_sort([]) == []
    assert bucket_sort([0.5]) == [0.5]
    assert bucket_sort([0.9, 0.1, 0.5, 0.3]) == [0.1, 0.3, 0.5, 0.9]
    assert bucket_sort([4, 4, 4, 4]) == [4, 4, 4, 4]
    assert bucket_sort([0.3, 0.1, 0.3, 0.2]) == [0.1, 0.2, 0.3, 0.3]
    src = [0.3, 0.1, 0.2]
    assert bucket_sort(src) == [0.1, 0.2, 0.3] and src == [0.3, 0.1, 0.2]
    assert stdlib_only()
    print("algo-09 OK")


if __name__ == "__main__":
    main()
