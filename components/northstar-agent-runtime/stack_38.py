"""Reverse a Stack using recursion-shaped iteration. IS: an explicit work-stack reversal without list.reverse(). IS NOT: in-place mutation of the caller's list."""

from __future__ import annotations

import ast

VERSION = "stack-38.v1"

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

def reverse_stack(stack: list[int]) -> list[int]:
    """Return the elements in reverse order. Fail-closed on bad input."""
    data = _req_int_list(stack, "stack")
    out: list[int] = []
    work = list(data)
    while work:
        out.append(work.pop())
    return out

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
    assert reverse_stack([1, 2, 3]) == [3, 2, 1]
    assert reverse_stack([]) == []
    assert reverse_stack([9]) == [9]
    src = [1, 2]
    reverse_stack(src)
    assert src == [1, 2]
    try:
        reverse_stack("ab")
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    assert stdlib_only()
    print("stack_38 OK")


if __name__ == "__main__":
    main()
