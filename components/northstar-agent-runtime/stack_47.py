"""Clear Digits by deleting the nearest left non-digit. IS: a char stack where each digit pops the closest letter to its left. IS NOT: deleting all letters; only one per digit."""

from __future__ import annotations

import ast

VERSION = "stack-47.v1"

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

def clear_digits(s: str) -> str:
    """Remove each digit and the nearest non-digit left of it.

    Fail-closed: lowercase letters and digits only.
    """
    s = _req_str(s, "s")
    if not all(ch.islower() or ch.isdigit() for ch in s):
        raise ValueError("s must contain lowercase letters and digits only")
    stack: list[str] = []
    for ch in s:
        if ch.isdigit():
            if stack and not stack[-1].isdigit():
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
    assert clear_digits("cb34") == ""
    assert clear_digits("abc123") == ""
    assert clear_digits("a1b2c3") == ""
    assert clear_digits("abc") == "abc"
    assert clear_digits("") == ""
    assert clear_digits("ab12") == ""
    try:
        clear_digits("aB1")
    except ValueError:
        pass
    else:
        raise AssertionError("uppercase must raise ValueError")
    assert stdlib_only()
    print("stack_47 OK")


if __name__ == "__main__":
    main()
