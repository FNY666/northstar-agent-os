"""Validate Stack Sequences by simulation. IS: a simulated push stack draining whenever the top matches popped. IS NOT: a permutation parity check."""

from __future__ import annotations

import ast

VERSION = "stack-23.v1"

def _req_seq(seq: object, name: str) -> list[int]:
    if not isinstance(seq, list):
        raise ValueError(f"{name} must be a list")
    for v in seq:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{name} must contain only ints")
    return list(seq)


def validate_stack_sequences(pushed: list[int], popped: list[int]) -> bool:
    """True iff ``popped`` is a valid pop order for ``pushed``. Fail-closed."""
    push = _req_seq(pushed, "pushed")
    pop = _req_seq(popped, "popped")
    if len(push) != len(pop):
        raise ValueError("pushed and popped must have equal length")
    stack: list[int] = []
    j = 0
    for x in push:
        stack.append(x)
        while stack and stack[-1] == pop[j]:
            stack.pop()
            j += 1
    return not stack

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
    assert validate_stack_sequences([1, 2, 3, 4, 5], [4, 5, 3, 2, 1]) is True
    assert validate_stack_sequences([1, 2, 3, 4, 5], [4, 3, 5, 1, 2]) is False
    assert validate_stack_sequences([], []) is True
    assert validate_stack_sequences([1], [1]) is True
    try:
        validate_stack_sequences([1, 2], [1])
    except ValueError:
        pass
    else:
        raise AssertionError("length mismatch must raise ValueError")
    assert stdlib_only()
    print("stack_23 OK")


if __name__ == "__main__":
    main()
