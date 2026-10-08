"""Remove Outermost Parentheses of each primitive. IS: a depth counter skipping chars at depth 0/1 transitions. IS NOT: removing all outer pairs recursively."""

from __future__ import annotations

import ast

VERSION = "stack-49.v1"

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

def remove_outermost(s: str) -> str:
    """Strip the outermost pair of every primitive block. Fail-closed."""
    s = _req_str(s, "s")
    for ch in s:
        if ch not in "()":
            raise ValueError(f"invalid character {ch!r}")
    out: list[str] = []
    depth = 0
    for ch in s:
        if ch == "(":
            if depth:
                out.append(ch)
            depth += 1
        else:
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced parentheses")
            if depth:
                out.append(ch)
    if depth:
        raise ValueError("unbalanced parentheses")
    return "".join(out)

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
    assert remove_outermost("(()())(())") == "()()()"
    assert remove_outermost("(()())(())(()(()))") == "()()()()(())"
    assert remove_outermost("()()") == ""
    assert remove_outermost("(())") == "()"
    assert remove_outermost("") == ""
    try:
        remove_outermost("(()")
    except ValueError:
        pass
    else:
        raise AssertionError("unbalanced must raise ValueError")
    assert stdlib_only()
    print("stack_49 OK")


if __name__ == "__main__":
    main()
