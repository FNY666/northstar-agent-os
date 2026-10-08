"""Build an Array With Stack Operations. IS: Push/Pop opcodes simulating reading 1..n to form target. IS NOT: actually building the array; returns the opcode list."""

from __future__ import annotations

import ast

VERSION = "stack-31.v1"

def _req_target_n(target: object, n: object) -> tuple[list[int], int]:
    if not isinstance(target, list):
        raise ValueError("target must be a list")
    for v in target:
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise ValueError("target must contain positive ints")
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    if sorted(target) != target or len(set(target)) != len(target):
        raise ValueError("target must be strictly increasing")
    if target and target[-1] > n:
        raise ValueError("target values must not exceed n")
    return list(target), n


def build_array_with_stack(target: list[int], n: int) -> list[str]:
    """Opcode list to build ``target`` from stream 1..n. Fail-closed."""
    target, n = _req_target_n(target, n)
    ops: list[str] = []
    want = set(target)
    for x in range(1, (target[-1] if target else 0) + 1):
        ops.append("Push")
        if x not in want:
            ops.append("Pop")
    return ops

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
    assert build_array_with_stack([1, 3], 3) == ["Push", "Push", "Pop", "Push"]
    assert build_array_with_stack([1, 2, 3], 3) == ["Push", "Push", "Push"]
    assert build_array_with_stack([1, 2], 4) == ["Push", "Push"]
    assert build_array_with_stack([], 5) == []
    try:
        build_array_with_stack([2, 1], 3)
    except ValueError:
        pass
    else:
        raise AssertionError("unsorted target must raise ValueError")
    try:
        build_array_with_stack([5], 3)
    except ValueError:
        pass
    else:
        raise AssertionError("target > n must raise ValueError")
    assert stdlib_only()
    print("stack_31 OK")


if __name__ == "__main__":
    main()
