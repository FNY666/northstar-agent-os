"""Remove All Adjacent Duplicates in String. IS: a character stack cancelling equal neighbours until stable. IS NOT: a single-pass regex; cascading cancellations are handled."""

from __future__ import annotations

import ast

VERSION = "stack-12.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_list(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return list(value)

def remove_adjacent_duplicates(s: str) -> str:
    """Remove adjacent duplicates repeatedly. Fail-closed on non-string."""
    s = _req_str(s, "s")
    stack: list[str] = []
    for ch in s:
        if stack and stack[-1] == ch:
            stack.pop()
        else:
            stack.append(ch)
    return "".join(stack)

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
    assert remove_adjacent_duplicates("abbaca") == "ca"
    assert remove_adjacent_duplicates("azxxzy") == "ay"
    assert remove_adjacent_duplicates("") == ""
    assert remove_adjacent_duplicates("a") == "a"
    assert remove_adjacent_duplicates("aa") == ""
    try:
        remove_adjacent_duplicates(123)
    except ValueError:
        pass
    else:
        raise AssertionError("non-string must raise ValueError")
    assert stdlib_only()
    print("stack_12 OK")


if __name__ == "__main__":
    main()
