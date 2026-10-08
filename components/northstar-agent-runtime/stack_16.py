"""Remove K Digits for the smallest possible number. IS: a monotonic increasing digit stack dropping larger predecessors. IS NOT: a numeric comparison of all subsequences."""

from __future__ import annotations

import ast

VERSION = "stack-16.v1"

def _req_num_k(num: object, k: object) -> tuple[str, int]:
    if not isinstance(num, str) or not num.isdigit():
        raise ValueError("num must be a digit string")
    if isinstance(k, bool) or not isinstance(k, int) or k < 0:
        raise ValueError("k must be a non-negative int")
    if k > len(num):
        raise ValueError("k must not exceed len(num)")
    return num, k


def remove_k_digits(num: str, k: int) -> str:
    """Smallest number after removing ``k`` digits. Fail-closed."""
    num, k = _req_num_k(num, k)
    stack: list[str] = []
    for d in num:
        while k and stack and stack[-1] > d:
            stack.pop()
            k -= 1
        stack.append(d)
    if k:
        stack = stack[:-k]
    result = "".join(stack).lstrip("0")
    return result or "0"

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    assert remove_k_digits("1432219", 3) == "1219"
    assert remove_k_digits("10200", 1) == "200"
    assert remove_k_digits("10", 2) == "0"
    assert remove_k_digits("112", 1) == "11"
    assert remove_k_digits("9", 0) == "9"
    try:
        remove_k_digits("12a", 1)
    except ValueError:
        pass
    else:
        raise AssertionError("non-digit must raise ValueError")
    try:
        remove_k_digits("12", 5)
    except ValueError:
        pass
    else:
        raise AssertionError("k > len must raise ValueError")
    assert stdlib_only()
    print("stack_16 OK")


if __name__ == "__main__":
    main()
