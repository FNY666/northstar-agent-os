"""Evaluate Infix Expression with two stacks. IS: Dijkstra's two-stack algorithm for +,-,*,/ and parentheses. IS NOT: supporting unary minus or variables."""

from __future__ import annotations

import ast

VERSION = "stack-42.v1"

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

def _apply(op: str, b: int, a: int) -> int:
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    if b == 0:
        raise ValueError("division by zero")
    return int(a / b)


def eval_infix(expr: str) -> int:
    """Evaluate an infix expression of non-negative integers.

    Fail-closed: malformed input or division by zero raises ValueError.
    """
    expr = _req_str(expr, "expr")
    prec = {"+": 1, "-": 1, "*": 2, "/": 2}
    vals: list[int] = []
    ops: list[str] = []
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if ch == " ":
            i += 1
            continue
        if ch.isdigit():
            j = i
            while j < n and expr[j].isdigit():
                j += 1
            vals.append(int(expr[i:j]))
            i = j
            continue
        if ch == "(":
            ops.append(ch)
        elif ch == ")":
            while ops and ops[-1] != "(":
                if len(vals) < 2:
                    raise ValueError("malformed expression")
                vals.append(_apply(ops.pop(), vals.pop(), vals.pop()))
            if not ops:
                raise ValueError("mismatched parentheses")
            ops.pop()
        elif ch in prec:
            while ops and ops[-1] != "(" and prec[ops[-1]] >= prec[ch]:
                if len(vals) < 2:
                    raise ValueError("malformed expression")
                vals.append(_apply(ops.pop(), vals.pop(), vals.pop()))
            ops.append(ch)
        else:
            raise ValueError(f"invalid character {ch!r}")
        i += 1
    while ops:
        if ops[-1] == "(":
            raise ValueError("mismatched parentheses")
        if len(vals) < 2:
            raise ValueError("malformed expression")
        vals.append(_apply(ops.pop(), vals.pop(), vals.pop()))
    if len(vals) != 1:
        raise ValueError("malformed expression")
    return vals[0]

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
    assert eval_infix("2+3*4") == 14
    assert eval_infix("(2+3)*4") == 20
    assert eval_infix("100 * 2 + 12") == 212
    assert eval_infix("100 * ( 2 + 12 ) / 14") == 100
    try:
        eval_infix("2+")
    except ValueError:
        pass
    else:
        raise AssertionError("malformed must raise ValueError")
    try:
        eval_infix("4/0")
    except ValueError:
        pass
    else:
        raise AssertionError("division by zero must raise ValueError")
    assert stdlib_only()
    print("stack_42 OK")


if __name__ == "__main__":
    main()
