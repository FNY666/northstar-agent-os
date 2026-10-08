"""Basic Calculator II for +,-,*,/ without parentheses. IS: a value stack applying *,/ immediately and deferring +,-. IS NOT: handling parentheses; use stack_46 for those."""

from __future__ import annotations

import ast

VERSION = "stack-50.v1"

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

def basic_calculator_ii(s: str) -> int:
    """Evaluate +,-,*,/ with integer division truncating toward zero.

    Fail-closed: digits, spaces and the four operators only.
    """
    s = _req_str(s, "s")
    stack: list[int] = []
    num = 0
    op = "+"
    for i, ch in enumerate(s + "+"):
        if ch == " ":
            continue
        if ch.isdigit():
            num = num * 10 + int(ch)
            continue
        if ch not in "+-*/":
            raise ValueError(f"invalid character {ch!r}")
        if op == "+":
            stack.append(num)
        elif op == "-":
            stack.append(-num)
        elif op == "*":
            stack.append(stack.pop() * num)
        else:
            top = stack.pop()
            if num == 0:
                raise ValueError("division by zero")
            stack.append(int(top / num))
        op = ch
        num = 0
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
    assert basic_calculator_ii("3+2*2") == 7
    assert basic_calculator_ii(" 3/2 ") == 1
    assert basic_calculator_ii(" 3+5 / 2 ") == 5
    assert basic_calculator_ii("14-3/2") == 13
    assert basic_calculator_ii("0") == 0
    try:
        basic_calculator_ii("3/0")
    except ValueError:
        pass
    else:
        raise AssertionError("division by zero must raise ValueError")
    try:
        basic_calculator_ii("2^3")
    except ValueError:
        pass
    else:
        raise AssertionError("'^' must raise ValueError")
    assert stdlib_only()
    print("stack_50 OK")


if __name__ == "__main__":
    main()
