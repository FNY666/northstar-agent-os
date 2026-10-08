"""Merge K Sorted Lists: merge several sorted lists into one sorted list IS: a k-way heap merge via heapq.merge IS NOT: concatenating then sorting"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-05.v1"

def _req_lists(value):
    if not isinstance(value, list):
        raise ValueError("lists must be a list of lists")
    out = []
    for i, sub in enumerate(value):
        if not isinstance(sub, list):
            raise ValueError(f"lists[{i}] must be a list")
        out.append(list(sub))
    return out


def merge_k_sorted(lists):
    """Merge sorted lists into a single sorted list.

    Fail-closed: input must be a list of lists, else :class:`ValueError`.
    """
    lists = _req_lists(lists)
    return list(heapq.merge(*lists)) if lists else []

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
    assert merge_k_sorted([[1, 4, 5], [1, 3, 4], [2, 6]]) == [1, 1, 2, 3, 4, 4, 5, 6]
    assert merge_k_sorted([]) == []
    assert merge_k_sorted([[], [1], []]) == [1]
    assert merge_k_sorted([[2], [1]]) == [1, 2]
    try:
        merge_k_sorted("nope")
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    assert stdlib_only()
    print("heap-05.v1 OK")


if __name__ == "__main__":
    main()
