"""Valid Parentheses: decide whether a bracket string is balanced. IS: a stack-based validator for '()[]{}' that pushes openers and matches closers. IS NOT: a general expression parser or a validator that tolerates unknown characters."""

from __future__ import annotations

import ast

VERSION = "stack-01.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_list(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return list(value)

def valid_parentheses(s: str) -> bool:
    """Return True iff every opener in ``s`` is closed in the correct order.

    Fail-closed: ``s`` must be a string containing only bracket characters,
    otherwise :class:`ValueError`.
    """
    s = _req_str(s, "s")
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    for ch in s:
        if ch in "([{":
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack.pop() != pairs[ch]:
                return False
        else:
            raise ValueError(f"invalid character {ch!r}")
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
    assert valid_parentheses("()[]{}") is True
    assert valid_parentheses("([)]") is False
    assert valid_parentheses("{[]}") is True
    assert valid_parentheses("") is True
    assert valid_parentheses("((") is False
    try:
        valid_parentheses("a(b)")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown char must raise ValueError")
    assert stdlib_only()
    print("stack_01 OK")


if __name__ == "__main__":
    main()
