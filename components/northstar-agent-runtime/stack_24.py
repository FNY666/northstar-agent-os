"""Remove Duplicate Letters for smallest lexicographic subsequence. IS: a monotonic stack keeping each letter once with last-occurrence lookahead. IS NOT: a simple sort; relative order constraints are respected."""

from __future__ import annotations

import ast

VERSION = "stack-24.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_list(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return list(value)

def remove_duplicate_letters(s: str) -> str:
    """Smallest lexicographic string with each letter exactly once.

    Fail-closed: lowercase letters only.
    """
    s = _req_str(s, "s")
    if not all("a" <= ch <= "z" for ch in s):
        raise ValueError("s must contain lowercase letters only")
    last = {ch: i for i, ch in enumerate(s)}
    stack: list[str] = []
    seen: set[str] = set()
    for i, ch in enumerate(s):
        if ch in seen:
            continue
        while stack and ch < stack[-1] and last[stack[-1]] > i:
            seen.discard(stack.pop())
        stack.append(ch)
        seen.add(ch)
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
    assert remove_duplicate_letters("bcabc") == "abc"
    assert remove_duplicate_letters("cbacdcbc") == "acdb"
    assert remove_duplicate_letters("a") == "a"
    assert remove_duplicate_letters("") == ""
    assert remove_duplicate_letters("bbcaac") == "bac"
    try:
        remove_duplicate_letters("aB")
    except ValueError:
        pass
    else:
        raise AssertionError("uppercase must raise ValueError")
    assert stdlib_only()
    print("stack_24 OK")


if __name__ == "__main__":
    main()
