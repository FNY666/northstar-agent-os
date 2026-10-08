"""Backtracking: Permutations.

Generates all permutations of a list of distinct elements by swapping each
position with every remaining position (classic backtracking over indices).

IS: all n! permutations for distinct elements; order is generation order.
IS NOT: permutations-with-duplicates (duplicates produce repeats); NOT itertools wrapper.
"""

from typing import List, TypeVar
import ast

VERSION = "backtrack_03.v1"

T = TypeVar("T")


def permutations(items: List[T]) -> List[List[T]]:
    result: List[List[T]] = []
    arr = list(items)

    def backtrack(i: int) -> None:
        if i == len(arr):
            result.append(list(arr))
            return
        for j in range(i, len(arr)):
            arr[i], arr[j] = arr[j], arr[i]
            backtrack(i + 1)
            arr[i], arr[j] = arr[j], arr[i]

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
    p = permutations([1, 2, 3])
    assert len(p) == 6
    assert sorted(tuple(x) for x in p) == sorted(
        [(1, 2, 3), (1, 3, 2), (2, 1, 3), (2, 3, 1), (3, 1, 2), (3, 2, 1)]
    )
    assert permutations([]) == [[]]
    assert permutations(["a"]) == [["a"]]
    assert len(permutations([1, 2, 3, 4])) == 24
    assert stdlib_only()
    print("backtrack_03 OK")


if __name__ == "__main__":
    main()
