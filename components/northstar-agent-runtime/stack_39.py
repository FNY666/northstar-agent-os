"""Delete the Middle Element of a Stack. IS: a temp-stack rebuild skipping the middle index. IS NOT: deleting by value; position is floor(n/2) from the top."""

from __future__ import annotations

import ast

VERSION = "stack-39.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_int_list(values: object, name: str) -> list[int]:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{name} must contain only ints")
    return list(values)

def delete_middle(stack: list[int]) -> list[int]:
    """Remove the middle element (top is the end of the list).

    Fail-closed: non-empty int list required.
    """
    data = _req_int_list(stack, "stack")
    if not data:
        raise ValueError("stack must be non-empty")
    mid = len(data) // 2
    tmp: list[int] = []
    for _ in range(mid):
        tmp.append(data.pop())
    data.pop()
    while tmp:
        data.append(tmp.pop())
    return data

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
    assert delete_middle([1, 2, 3, 4, 5]) == [1, 2, 4, 5]
    assert delete_middle([1, 2, 3, 4]) == [1, 3, 4]
    assert delete_middle([9]) == []
    assert delete_middle([1, 2]) == [2]
    try:
        delete_middle([])
    except ValueError:
        pass
    else:
        raise AssertionError("empty stack must raise ValueError")
    assert stdlib_only()
    print("stack_39 OK")


if __name__ == "__main__":
    main()
