"""merge_overlapping_intervals (two-pointer), merge overlapping intervals from a sorted list. IS: a single two-pointer scan merging runs of overlapping [start, end] pairs. IS NOT: a sorter - input must already be sorted by start."""
from __future__ import annotations

import ast

VERSION = "twop-49.v1"


def merge_overlapping_intervals(intervals: list[list[int]]) -> list[list[int]]:
    """Merge overlapping intervals; input must be sorted by start. Returns new lists."""
    if not isinstance(intervals, list):
        raise ValueError("intervals must be a list")
    for iv in intervals:
        if (
            not isinstance(iv, list)
            or len(iv) != 2
            or isinstance(iv[0], bool)
            or isinstance(iv[1], bool)
            or not isinstance(iv[0], (int, float))
            or not isinstance(iv[1], (int, float))
        ):
            raise ValueError("each interval must be a [start, end] pair of numbers")
        if iv[0] > iv[1]:
            raise ValueError("interval start must not exceed end")
    if any(intervals[i][0] > intervals[i + 1][0] for i in range(len(intervals) - 1)):
        raise ValueError("intervals must be sorted by start")
    if not intervals:
        return []
    merged: list[list[int]] = [[intervals[0][0], intervals[0][1]]]
    cur_start, cur_end = intervals[0][0], intervals[0][1]
    for start, end in intervals[1:]:
        if start <= cur_end:
            if end > cur_end:
                cur_end = end
                merged[-1][1] = end
        else:
            cur_start, cur_end = start, end
            merged.append([start, end])
    return merged


def stdlib_only() -> bool:
    """AST-parse this file; return False if any import outside the allowed set appears."""
    import pathlib
    src = pathlib.Path(__file__).read_text()
    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert merge_overlapping_intervals([[1, 3], [2, 6], [8, 10], [15, 18]]) == [
        [1, 6], [8, 10], [15, 18]]
    assert merge_overlapping_intervals([[1, 4], [4, 5]]) == [[1, 5]]  # touching edges merge
    assert merge_overlapping_intervals([[1, 10], [2, 3], [4, 5]]) == [[1, 10]]  # edge: fully nested
    assert merge_overlapping_intervals([]) == []
    assert merge_overlapping_intervals([[5, 7]]) == [[5, 7]]
    try:
        merge_overlapping_intervals([[2, 3], [1, 4]])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unsorted input")
    try:
        merge_overlapping_intervals([[3, 1]])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for start > end")
    assert stdlib_only()
    print("merge_overlapping_intervals OK")


if __name__ == "__main__":
    main()
