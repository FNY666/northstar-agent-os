"""Distant Barcodes: rearrange barcodes so no two adjacent are equal IS: max-heap placement avoiding the previous barcode IS NOT: backtracking over permutations"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-34.v1"

def _req_barcodes(value):
    if not isinstance(value, list) or not value:
        raise ValueError("barcodes must be a non-empty list")
    for i, x in enumerate(value):
        if isinstance(x, bool) or not isinstance(x, int):
            raise ValueError(f"barcodes[{i}] must be an int")
    return list(value)


def rearrange_barcodes(barcodes):
    """Return a rearrangement with no adjacent duplicates.

    Fail-closed: bad input raises :class:`ValueError`. A valid input is
    assumed to admit a solution (max frequency <= (n+1)//2).
    """
    barcodes = _req_barcodes(barcodes)
    freq = {}
    for x in barcodes:
        freq[x] = freq.get(x, 0) + 1
    heap = [(-c, x) for x, c in freq.items()]
    heapq.heapify(heap)
    out = []
    while heap:
        neg_c, x = heapq.heappop(heap)
        if out and out[-1] == x:
            neg_c2, x2 = heapq.heappop(heap)
            out.append(x2)
            if neg_c2 + 1 < 0:
                heapq.heappush(heap, (neg_c2 + 1, x2))
            heapq.heappush(heap, (neg_c, x))
        else:
            out.append(x)
            if neg_c + 1 < 0:
                heapq.heappush(heap, (neg_c + 1, x))
    return out

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
    assert rearrange_barcodes([1, 1, 1, 2, 2, 2]) == [1, 2, 1, 2, 1, 2]
    assert rearrange_barcodes([1, 1, 1, 1, 2, 2, 3, 3]) == [1, 2, 1, 3, 1, 2, 1, 3]
    got = rearrange_barcodes([5])
    assert got == [5]
    got = rearrange_barcodes([2, 2, 1])
    assert all(got[i] != got[i + 1] for i in range(len(got) - 1)), got
    try:
        rearrange_barcodes([])
    except ValueError:
        pass
    else:
        raise AssertionError("empty list must raise ValueError")
    assert stdlib_only()
    print("heap-34.v1 OK")


if __name__ == "__main__":
    main()
