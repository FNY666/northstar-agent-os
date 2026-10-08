"""Score of Parentheses with a depth stack. IS: a stack tracking nesting depth; '()' scores 2**depth. IS NOT: a recursive descent parser."""

from __future__ import annotations

import ast

VERSION = "stack-18.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_list(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return list(value)

def score_of_parentheses(s: str) -> int:
    """Score: '()' = 1, AB = A+B, '(A)' = 2*A. Fail-closed."""
    s = _req_str(s, "s")
    for ch in s:
        if ch not in "()":
            raise ValueError(f"invalid character {ch!r}")
    stack = [0]
    for ch in s:
        if ch == "(":
            stack.append(0)
        else:
            if len(stack) < 2:
                raise ValueError("unbalanced parentheses")
            v = stack.pop()
            stack[-1] += max(2 * v, 1)
    if len(stack) != 1:
        raise ValueError("unbalanced parentheses")
    return stack[0]

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
    assert score_of_parentheses("()") == 1
    assert score_of_parentheses("(())") == 2
    assert score_of_parentheses("()()") == 2
    assert score_of_parentheses("(()(()))") == 6
    assert score_of_parentheses("") == 0
    try:
        score_of_parentheses("(()")
    except ValueError:
        pass
    else:
        raise AssertionError("unbalanced must raise ValueError")
    assert stdlib_only()
    print("stack_18 OK")


if __name__ == "__main__":
    main()
