"""Evaluate Reverse Polish Notation with truncating division. IS: a stack evaluator for +,-,*,/ where '/' truncates toward zero. IS NOT: an infix evaluator and does not support floats or variables."""

from __future__ import annotations

import ast

VERSION = "stack-03.v1"

def _req_tokens(tokens: object) -> list[str]:
    if not isinstance(tokens, list) or not all(isinstance(t, str) for t in tokens):
        raise ValueError("tokens must be a list of strings")
    return list(tokens)


def eval_rpn(tokens: list[str]) -> int:
    """Evaluate an RPN expression; division truncates toward zero.

    Fail-closed: malformed expressions, unknown tokens, or division by
    zero raise :class:`ValueError`.
    """
    toks = _req_tokens(tokens)
    stack: list[int] = []
    for tok in toks:
        if tok in {"+", "-", "*", "/"}:
            if len(stack) < 2:
                raise ValueError("not enough operands")
            b, a = stack.pop(), stack.pop()
            if tok == "+":
                stack.append(a + b)
            elif tok == "-":
                stack.append(a - b)
            elif tok == "*":
                stack.append(a * b)
            else:
                if b == 0:
                    raise ValueError("division by zero")
                stack.append(int(a / b))
        else:
            try:
                stack.append(int(tok))
            except ValueError:
                raise ValueError(f"invalid token {tok!r}") from None
    if len(stack) != 1:
        raise ValueError("malformed RPN expression")
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
    assert eval_rpn(["2", "1", "+", "3", "*"]) == 9
    assert eval_rpn(["4", "13", "5", "/", "+"]) == 6
    assert eval_rpn(["-7", "3", "/"]) == -2
    assert eval_rpn(["18"]) == 18
    try:
        eval_rpn(["2", "+"])
    except ValueError:
        pass
    else:
        raise AssertionError("underflow must raise ValueError")
    try:
        eval_rpn(["4", "0", "/"])
    except ValueError:
        pass
    else:
        raise AssertionError("division by zero must raise ValueError")
    assert stdlib_only()
    print("stack_03 OK")


if __name__ == "__main__":
    main()
