"""Top K Frequent Elements: return the k most frequent elements via a heap IS: count frequencies then pick the k largest by count IS NOT: a Counter.most_common call or a full sort"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-04.v1"

def _req_nums(value, name):
    if not isinstance(value, list) or not value:
        raise ValueError(f"{name} must be a non-empty list")
    return list(value)


def _req_k(k, distinct):
    if isinstance(k, bool) or not isinstance(k, int):
        raise ValueError("k must be an int")
    if not 1 <= k <= distinct:
        raise ValueError("k must satisfy 1 <= k <= number of distinct elements")
    return k


def top_k_frequent(nums, k):
    """Return the k most frequent elements of ``nums`` (any order).

    Fail-closed: ``nums`` must be a non-empty list and
    ``1 <= k <= distinct`` else :class:`ValueError`.
    """
    nums = _req_nums(nums, "nums")
    freq = {}
    for x in nums:
        freq[x] = freq.get(x, 0) + 1
    k = _req_k(k, len(freq))
    return heapq.nlargest(k, freq, key=freq.get)

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "heapq", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert sorted(top_k_frequent([1, 1, 1, 2, 2, 3], 2)) == [1, 2]
    assert top_k_frequent([1], 1) == [1]
    assert sorted(top_k_frequent([4, 4, 4, 6, 6, 8, 8, 8, 8], 2)) == [4, 8]
    try:
        top_k_frequent([], 1)
    except ValueError:
        pass
    else:
        raise AssertionError("empty nums must raise ValueError")
    try:
        top_k_frequent([1, 2], 5)
    except ValueError:
        pass
    else:
        raise AssertionError("k > distinct must raise ValueError")
    assert stdlib_only()
    print("heap-04.v1 OK")


if __name__ == "__main__":
    main()
