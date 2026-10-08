"""Longest Happy String: longest string without three consecutive equal letters IS: max-heap greedy appending up to two of the top character IS NOT: backtracking over all strings"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-33.v1"

def _req_counts(a, b, c):
    for name, v in (("a", a), ("b", b), ("c", c)):
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ValueError(f"{name} must be a non-negative int")
    return a, b, c


def longest_diverse_string(a, b, c):
    """Return a longest string with no ``aaa``/``bbb``/``ccc`` run.

    Fail-closed: counts must be non-negative ints, else :class:`ValueError`.
    """
    a, b, c = _req_counts(a, b, c)
    heap = [(-n, ch) for n, ch in ((a, "a"), (b, "b"), (c, "c")) if n > 0]
    heapq.heapify(heap)
    out = []
    while heap:
        neg_n, ch = heapq.heappop(heap)
        if len(out) >= 2 and out[-1] == ch and out[-2] == ch:
            if not heap:
                break
            neg_n2, ch2 = heapq.heappop(heap)
            out.append(ch2)
            if neg_n2 + 1 < 0:
                heapq.heappush(heap, (neg_n2 + 1, ch2))
            heapq.heappush(heap, (neg_n, ch))
        else:
            take = 2 if neg_n <= -2 else 1
            out.extend([ch] * take)
            if neg_n + take < 0:
                heapq.heappush(heap, (neg_n + take, ch))
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
    got = longest_diverse_string(1, 1, 7)
    assert got == "ccaccbcc", got
    got = longest_diverse_string(2, 2, 1)
    assert got == "aabbc", got
    assert longest_diverse_string(7, 1, 0) == "aabaa"
    assert longest_diverse_string(0, 0, 0) == ""
    for s in (longest_diverse_string(1, 1, 7), longest_diverse_string(2, 2, 1)):
        assert "aaa" not in s and "bbb" not in s and "ccc" not in s
    try:
        longest_diverse_string(-1, 0, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("negative count must raise ValueError")
    assert stdlib_only()
    print("heap-33.v1 OK")


if __name__ == "__main__":
    main()
