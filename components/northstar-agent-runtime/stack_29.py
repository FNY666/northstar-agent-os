"""Check If Word Is Valid After Substitutions of 'abc'. IS: a stack collapsing 'abc' triples as they form. IS NOT: a grammar parser; only the single production abc is allowed."""

from __future__ import annotations

import ast

VERSION = "stack-29.v1"

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

def is_valid_after_substitutions(s: str) -> bool:
    """True iff ``s`` reduces to empty by deleting 'abc'. Fail-closed."""
    s = _req_str(s, "s")
    if not all(ch in "abc" for ch in s):
        raise ValueError("s must contain only a, b, c")
    stack: list[str] = []
    for ch in s:
        stack.append(ch)
        if len(stack) >= 3 and stack[-3:] == ["a", "b", "c"]:
            del stack[-3:]
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
    assert is_valid_after_substitutions("aabcbc") is True
    assert is_valid_after_substitutions("abcabcababcc") is True
    assert is_valid_after_substitutions("abccba") is False
    assert is_valid_after_substitutions("") is True
    assert is_valid_after_substitutions("abc") is True
    try:
        is_valid_after_substitutions("abd")
    except ValueError:
        pass
    else:
        raise AssertionError("bad char must raise ValueError")
    assert stdlib_only()
    print("stack_29 OK")


if __name__ == "__main__":
    main()
