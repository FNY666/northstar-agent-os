"""Set helpers: jaccard, overlap, multi-difference, subset-any. What this IS: set algebra one-liners. What this IS NOT: not fuzzy matching."""

from __future__ import annotations

import ast


#: Module version.
UTIL_25_VERSION = "util-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-25.v1"


def jaccard(a, b) -> float:
    a, b = set(a), set(b)
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


def overlap(a, b):
    return set(a) & set(b)


def difference_all(a, *others):
    out = set(a)
    for o in others:
        out -= set(o)
    return out


def is_subset_of_any(s, candidates) -> bool:
    s = set(s)
    return any(s <= set(c) for c in candidates)


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
    assert jaccard({1, 2}, {2, 3}) == 1 / 3
    assert jaccard(set(), set()) == 1.0
    assert overlap([1, 2], [2, 3]) == {2}
    assert difference_all({1, 2, 3}, {2}, {3}) == {1}
    assert is_subset_of_any({1}, [{1, 2}, {3}]) is True
    assert is_subset_of_any({9}, [{1, 2}]) is False
    print("set helpers OK")


if __name__ == "__main__":
    main()
