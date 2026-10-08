"""Backtracking: Subsets / power set.

Generates all 2^n subsets of a list via the include/exclude decision at
each index (classic backtracking choice tree).

IS: the full power set of the input list, including the empty set.
IS NOT: the distinct-subsets variant (input duplicates produce repeat subsets).
"""

from typing import List, TypeVar
import ast

VERSION = "backtrack_05.v1"

T = TypeVar("T")


def subsets(items: List[T]) -> List[List[T]]:
    result: List[List[T]] = []
    current: List[T] = []

    def backtrack(i: int) -> None:
        if i == len(items):
            result.append(list(current))
            return
        current.append(items[i])
        backtrack(i + 1)
        current.pop()
        backtrack(i + 1)

    backtrack(0)
    return result


def stdlib_only() -> bool:
    allowed = {"typing", "ast"}
    with open(__file__) as f:
        tree = ast.parse(f.read())
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
    s = subsets([1, 2, 3])
    assert len(s) == 8
    assert [] in s and [1, 2, 3] in s and [1, 3] in s
    assert subsets([]) == [[]]
    assert len(subsets([1, 2, 3, 4])) == 16
    assert len({tuple(sorted(x)) for x in subsets([1, 2])}) == 4
    assert stdlib_only()
    print("backtrack_05 OK")


if __name__ == "__main__":
    main()
