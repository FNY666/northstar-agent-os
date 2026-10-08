"""Maximum Nesting Depth of Parentheses. IS: a depth counter tracking the deepest open level. IS NOT: validating balance; assumes the input is a VPS."""

from __future__ import annotations

import ast

VERSION = "stack-32.v1"

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

def max_nesting_depth(s: str) -> int:
    """Maximum depth of nested parentheses. Fail-closed on bad input."""
    s = _req_str(s, "s")
    depth = best = 0
    for ch in s:
        if ch == "(":
            depth += 1
            best = max(best, depth)
        elif ch == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced parentheses")
        elif not (ch.isdigit() or ch in "+-*/ "):
            raise ValueError(f"invalid character {ch!r}")
    if depth != 0:
        raise ValueError("unbalanced parentheses")
    return best

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
    assert max_nesting_depth("(1+(2*3)+((8)/4))+1".replace(")+1", ")")) == 3
    assert max_nesting_depth("(1)+((2))+(((3)))") == 3
    assert max_nesting_depth("1+(2*3)/(2-1)") == 1
    assert max_nesting_depth("1") == 0
    try:
        max_nesting_depth("(()")
    except ValueError:
        pass
    else:
        raise AssertionError("unbalanced must raise ValueError")
    try:
        max_nesting_depth("(a)")
    except ValueError:
        pass
    else:
        raise AssertionError("bad char must raise ValueError")
    assert stdlib_only()
    print("stack_32 OK")


if __name__ == "__main__":
    main()
