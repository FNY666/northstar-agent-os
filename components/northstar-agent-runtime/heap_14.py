"""Reorganize String: rearrange a string so no two adjacent chars are equal IS: max-heap greedy placement by remaining count IS NOT: backtracking over all permutations"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-14.v1"

def _req_str(value):
    if not isinstance(value, str) or not value:
        raise ValueError("s must be a non-empty string")
    return value


def reorganize_string(s):
    """Return a rearrangement with no adjacent duplicates, or "" if impossible.

    Fail-closed: ``s`` must be a non-empty string, else :class:`ValueError`.
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
        if out and out[-1] == ch:
            if not heap:
                return ""
            neg_c2, ch2 = heapq.heappop(heap)
            out.append(ch2)
            if neg_c2 + 1 < 0:
                heapq.heappush(heap, (neg_c2 + 1, ch2))
            heapq.heappush(heap, (neg_c, ch))
        else:
            out.append(ch)
            if neg_c + 1 < 0:
                heapq.heappush(heap, (neg_c + 1, ch))
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
    assert reorganize_string("aab") == "aba"
    assert reorganize_string("aaab") == ""
    assert reorganize_string("a") == "a"
    got = reorganize_string("vvvlo")
    assert len(got) == 5 and all(got[i] != got[i + 1] for i in range(4)), got
    try:
        reorganize_string("")
    except ValueError:
        pass
    else:
        raise AssertionError("empty s must raise ValueError")
    assert stdlib_only()
    print("heap-14.v1 OK")


if __name__ == "__main__":
    main()
