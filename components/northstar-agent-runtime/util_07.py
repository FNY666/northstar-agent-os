"""List helpers: chunk, dedupe, flatten-one, partition, sliding window. What this IS: batch/iteration plumbing. What this IS NOT: not numpy."""

from __future__ import annotations

import ast


#: Module version.
UTIL_07_VERSION = "util-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-07.v1"


class ListError(Exception):
    """List helper failure."""


def chunk(lst, n):
    if n <= 0:
        raise ListError("n must be positive")
    lst = list(lst)
    return [lst[i : i + n] for i in range(0, len(lst), n)]


def dedupe(lst):
    """Order-preserving dedupe (hashable items)."""
    seen = set()
    out = []
    for x in lst:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def flatten_one(lst):
    out = []
    for x in lst:
        if isinstance(x, (list, tuple)):
            out.extend(x)
        else:
            out.append(x)
    return out


def partition(lst, pred):
    yes, no = [], []
    for x in lst:
        (yes if pred(x) else no).append(x)
    return yes, no


def sliding_window(lst, size):
    if size <= 0:
        raise ListError("size must be positive")
    lst = list(lst)
    return [lst[i : i + size] for i in range(len(lst) - size + 1)]


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib']
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
    assert chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]
    assert dedupe([1, 2, 1, 3]) == [1, 2, 3]
    assert flatten_one([[1], 2, (3,)]) == [1, 2, 3]
    assert partition([1, 2, 3], lambda x: x % 2) == ([1, 3], [2])
    assert sliding_window([1, 2, 3], 2) == [[1, 2], [2, 3]]
    print("list helpers OK")


if __name__ == "__main__":
    main()
