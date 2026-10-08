"""Sort a Stack with one auxiliary stack. IS: insertion-style sorting using a temporary stack. IS NOT: converting to a list and calling sorted()."""

from __future__ import annotations

import ast

VERSION = "stack-37.v1"

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

def sort_stack(stack: list[int]) -> list[int]:
    """Return the stack's elements sorted ascending (bottom to top).

    Uses one auxiliary stack; the input list is not mutated. Fail-closed:
    input must be a list of ints.
    """
    data = _req_int_list(stack, "stack")
    work = list(data)
    tmp: list[int] = []
    while work:
        x = work.pop()
        while tmp and tmp[-1] > x:
            work.append(tmp.pop())
        tmp.append(x)
    return tmp


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
    assert sort_stack([3, 1, 2]) == [1, 2, 3]
    assert sort_stack([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert sort_stack([]) == []
    assert sort_stack([7]) == [7]
    assert sort_stack([2, 2, 1]) == [1, 2, 2]
    try:
        sort_stack([1, "2"])
    except ValueError:
        pass
    else:
        raise AssertionError("non-int must raise ValueError")
    assert stdlib_only()
    print("stack_37 OK")


if __name__ == "__main__":
    main()
