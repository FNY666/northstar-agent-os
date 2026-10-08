"""Baseball Game score from stack operations. IS: a score stack implementing integer, '+', 'D' and 'C' ops. IS NOT: a generic RPN evaluator."""

from __future__ import annotations

import ast

VERSION = "stack-11.v1"

def _req_ops(ops: object) -> list[str]:
    if not isinstance(ops, list) or not all(isinstance(o, str) for o in ops):
        raise ValueError("ops must be a list of strings")
    return list(ops)


def baseball_game(ops: list[str]) -> int:
    """Total score after applying the ops. Fail-closed on bad input."""
    operations = _req_ops(ops)
    stack: list[int] = []
    for op in operations:
        if op == "+":
            if len(stack) < 2:
                raise ValueError("'+' needs two previous scores")
            stack.append(stack[-1] + stack[-2])
        elif op == "D":
            if not stack:
                raise ValueError("'D' needs a previous score")
            stack.append(2 * stack[-1])
        elif op == "C":
            if not stack:
                raise ValueError("'C' needs a previous score")
            stack.pop()
        else:
            try:
                stack.append(int(op))
            except ValueError:
                raise ValueError(f"invalid op {op!r}") from None
    return sum(stack)

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
    assert baseball_game(["5", "2", "C", "D", "+"]) == 30
    assert baseball_game(["5", "-2", "4", "C", "D", "9", "+", "+"]) == 27
    assert baseball_game(["1"]) == 1
    assert baseball_game([]) == 0
    try:
        baseball_game(["+"])
    except ValueError:
        pass
    else:
        raise AssertionError("'+' without history must raise ValueError")
    try:
        baseball_game(["x"])
    except ValueError:
        pass
    else:
        raise AssertionError("bad op must raise ValueError")
    assert stdlib_only()
    print("stack_11 OK")


if __name__ == "__main__":
    main()
