"""Sort Characters By Frequency: sort characters of a string by descending frequency IS: max-heap over character frequencies with deterministic tie-break IS NOT: a plain sort by count without a heap"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-15.v1"

def _req_str(value):
    if not isinstance(value, str):
        raise ValueError("s must be a string")
    return value


def frequency_sort(s):
    """Return ``s`` sorted by descending character frequency.

    Fail-closed: ``s`` must be a string, else :class:`ValueError`.
    Ties break by character for determinism.
    """
    s = _req_str(s)
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    heap = [(-c, ch) for ch, c in freq.items()]
    heapq.heapify(heap)
    out = []
    while heap:
        neg_c, ch = heapq.heappop(heap)
        out.append(ch * (-neg_c))
    return "".join(out)

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
    assert frequency_sort("tree") == "eert"
    assert frequency_sort("cccaaa") == "aaaccc"
    assert frequency_sort("Aabb") == "bbAa"
    assert frequency_sort("") == ""
    try:
        frequency_sort(123)
    except ValueError:
        pass
    else:
        raise AssertionError("non-string must raise ValueError")
    assert stdlib_only()
    print("heap-15.v1 OK")


if __name__ == "__main__":
    main()
