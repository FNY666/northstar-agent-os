"""Number of Students Unable to Eat Lunch. IS: a count-based simulation of the queue/stack sandwich process. IS NOT: stepping the queue element by element."""

from __future__ import annotations

import ast

VERSION = "stack-34.v1"

def _req_binary(seq: object, name: str) -> list[int]:
    if not isinstance(seq, list):
        raise ValueError(f"{name} must be a list")
    for v in seq:
        if v not in (0, 1):
            raise ValueError(f"{name} must contain only 0/1")
    return list(seq)


def count_students(students: list[int], sandwiches: list[int]) -> int:
    """Students left hungry after the lunch process. Fail-closed."""
    stud = _req_binary(students, "students")
    sand = _req_binary(sandwiches, "sandwiches")
    if len(stud) != len(sand):
        raise ValueError("students and sandwiches must have equal length")
    want = [stud.count(0), stud.count(1)]
    for sw in sand:
        if want[sw] == 0:
            break
        want[sw] -= 1
    return sum(want)

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
    assert count_students([1, 1, 0, 0], [0, 1, 0, 1]) == 0
    assert count_students([1, 1, 1, 0, 0, 1], [1, 0, 0, 0, 1, 1]) == 3
    assert count_students([0], [1]) == 1
    assert count_students([], []) == 0
    try:
        count_students([0, 1], [0])
    except ValueError:
        pass
    else:
        raise AssertionError("length mismatch must raise ValueError")
    try:
        count_students([0, 2], [0, 1])
    except ValueError:
        pass
    else:
        raise AssertionError("non-binary must raise ValueError")
    assert stdlib_only()
    print("stack_34 OK")


if __name__ == "__main__":
    main()
