"""Backtracking: Split string into Fibonacci sequence -- cut a digit string into
a Fibonacci-like sequence of at least 3 numbers.

IS: backtracking over split positions with leading-zero rejection, 32-bit
signed-int bound, and the sum-equality pruning rule (break when the next
value exceeds the required sum).
IS NOT: the additive-number boolean (which need not consume the whole
string), negative numbers, or bases other than 10.
"""

from __future__ import annotations

VERSION = "backtrack_49.v1"


import ast
from typing import List, Optional

_ALLOWED_IMPORTS = {"__future__", "ast", "typing", "dataclasses", "itertools",
                    "functools", "collections", "math", "re", "string", "sys"}

_LIMIT = 2 ** 31 - 1


def split_into_fibonacci(num: str) -> List[int]:
    """Split num into a Fibonacci-like sequence; [] if impossible."""
    n = len(num)

    def backtrack(start: int, seq: List[int]) -> Optional[List[int]]:
        if start == n:
            return list(seq) if len(seq) >= 3 else None
        value = 0
        for end in range(start, n):
            if end > start and num[start] == "0":
                break  # leading zero: only the single "0" is legal
            value = value * 10 + int(num[end])
            if value > _LIMIT:
                break
            if len(seq) >= 2 and value > seq[-1] + seq[-2]:
                break  # overshot the required next Fibonacci value
            if len(seq) < 2 or value == seq[-1] + seq[-2]:
                seq.append(value)
                found = backtrack(end + 1, seq)
                if found is not None:
                    return found
                seq.pop()
        return None

    return backtrack(0, []) or []


def stdlib_only() -> bool:
    """Return True only if every import in this file comes from the allowed stdlib set."""
    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.module.split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert split_into_fibonacci("11235813") == [1, 1, 2, 3, 5, 8, 13]
    assert split_into_fibonacci("123456579") == [123, 456, 579]
    assert split_into_fibonacci("112358130") == []
    assert split_into_fibonacci("0123") == []
    assert split_into_fibonacci("1101111") == [11, 0, 11, 11]
    seq = split_into_fibonacci("11235813")
    assert all(seq[i] + seq[i + 1] == seq[i + 2] for i in range(len(seq) - 2))
    print("backtrack_49 OK")


if __name__ == "__main__":
    main()
