"""Basic Calculator for +,- and parentheses. IS: a sign stack evaluating sums with nested scopes. IS NOT: handling *,/ or unary plus chains beyond '-('."""

from __future__ import annotations

import ast

VERSION = "stack-46.v1"

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

def basic_calculator(s: str) -> int:
    """Evaluate an expression of non-negative ints with +,-,(). Fail-closed."""
    s = _req_str(s, "s")
    total = 0
    sign = 1
    stack: list[int] = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch.isdigit():
            j = i
            while j < n and s[j].isdigit():
                j += 1
            total += sign * int(s[i:j])
            i = j
            continue
        if ch == "+":
            sign = 1
        elif ch == "-":
            sign = -1
        elif ch == "(":
            stack.append(total)
            stack.append(sign)
            total = 0
            sign = 1
        elif ch == ")":
            if len(stack) < 2:
                raise ValueError("mismatched parentheses")
            total = total * stack.pop() + stack.pop()
        elif ch != " ":
            raise ValueError(f"invalid character {ch!r}")
        i += 1
    if stack:
        raise ValueError("mismatched parentheses")
    return total

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
    assert basic_calculator("1 + 1") == 2
    assert basic_calculator(" 2-1 + 2 ") == 3
    assert basic_calculator("(1+(4+5+2)-3)+(6+8)") == 23
    assert basic_calculator("-(3+2)") == -5
    try:
        basic_calculator("(1+2")
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched must raise ValueError")
    try:
        basic_calculator("1*2")
    except ValueError:
        pass
    else:
        raise AssertionError("'*' must raise ValueError")
    assert stdlib_only()
    print("stack_46 OK")


if __name__ == "__main__":
    main()
