"""Infix to Postfix conversion (shunting-yard). IS: an operator stack with precedence handling for +,-,*,/,^ and parens. IS NOT: an evaluator; output is a postfix token string."""

from __future__ import annotations

import ast

VERSION = "stack-41.v1"

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

_PREC = {"+": 1, "-": 1, "*": 2, "/": 2, "^": 3}


def infix_to_postfix(expr: str) -> str:
    """Convert infix to postfix tokens joined by spaces. Fail-closed."""
    expr = _req_str(expr, "expr")
    out: list[str] = []
    ops: list[str] = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == " ":
            i += 1
            continue
        if ch.isalnum():
            j = i
            while j < len(expr) and expr[j].isalnum():
                j += 1
            out.append(expr[i:j])
            i = j
            continue
        if ch == "(":
            ops.append(ch)
        elif ch == ")":
            while ops and ops[-1] != "(":
                out.append(ops.pop())
            if not ops:
                raise ValueError("mismatched parentheses")
            ops.pop()
        elif ch in _PREC:
            while ops and ops[-1] != "(" and _PREC[ops[-1]] >= _PREC[ch]:
                out.append(ops.pop())
            ops.append(ch)
        else:
            raise ValueError(f"invalid character {ch!r}")
        i += 1
    while ops:
        if ops[-1] == "(":
            raise ValueError("mismatched parentheses")
        out.append(ops.pop())
    return " ".join(out)

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
    assert infix_to_postfix("a+b*c") == "a b c * +"
    assert infix_to_postfix("(a+b)*c") == "a b + c *"
    assert infix_to_postfix("a+b*(c^d-e)") == "a b c d ^ e - * +"
    assert infix_to_postfix("a") == "a"
    try:
        infix_to_postfix("(a+b")
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched paren must raise ValueError")
    try:
        infix_to_postfix("a&b")
    except ValueError:
        pass
    else:
        raise AssertionError("bad char must raise ValueError")
    assert stdlib_only()
    print("stack_41 OK")


if __name__ == "__main__":
    main()
