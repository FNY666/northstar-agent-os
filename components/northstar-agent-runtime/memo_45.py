"""Memoized Remove Boxes: memoization example.

Max points removing boxes: state (l, r, k) with k same-colored boxes attached to r; either remove the group or merge with an equal box inside. The (l, r, k) cache prunes the exponential search.

What this IS: a real memoized remove-boxes maximizer with same-color merging.
What this IS NOT: a removal-sequence builder; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_45_VERSION = "memo-remove-boxes.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-remove-boxes.v1"


class MemoError(Exception):
    """Fail-closed."""


def remove_boxes(boxes: tuple, l: int = 0, r: int | None = None, k: int = 0, _cache: dict | None = None) -> int:
    """Memoized remove-boxes max score for boxes[l..r] with k attached to r."""
    if r is None:
        r = len(boxes) - 1
    cache: dict = _cache if _cache is not None else {}
    key = (l, r, k)
    if key in cache:
        return cache[key]
    if l > r:
        cache[key] = 0
    else:
        rr, kk = r, k
        while rr > l and boxes[rr] == boxes[rr - 1]:
            rr -= 1
            kk += 1
        best = remove_boxes(boxes, l, rr - 1, 0, cache) + (kk + 1) * (kk + 1)
        for i in range(l, rr):
            if boxes[i] == boxes[rr]:
                best = max(
                    best,
                    remove_boxes(boxes, l, i, kk + 1, cache) + remove_boxes(boxes, i + 1, rr - 1, 0, cache),
                )
        cache[key] = best
    return cache[key]

def test_remove_boxes_example():
    assert remove_boxes((1, 3, 2, 2, 2, 3, 4, 3, 1)) == 23


def test_remove_boxes_single():
    assert remove_boxes((5,)) == 1


def test_remove_boxes_empty():
    assert remove_boxes(()) == 0

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    test_remove_boxes_example()
    test_remove_boxes_single()
    test_remove_boxes_empty()
    assert stdlib_only()
    print("memo-45 OK: remove-boxes")


if __name__ == "__main__":
    main()
