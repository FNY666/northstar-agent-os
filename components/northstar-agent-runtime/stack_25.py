"""Remove All Adjacent Duplicates in String II (k-group). IS: a (char, run-length) stack deleting runs of length k. IS NOT: a regex; runs reform across deletions."""

from __future__ import annotations

import ast

VERSION = "stack-25.v1"

def _req_s_k(s: object, k: object) -> tuple[str, int]:
    if not isinstance(s, str):
        raise ValueError("s must be a string")
    if isinstance(k, bool) or not isinstance(k, int) or k < 2:
        raise ValueError("k must be an int >= 2")
    return s, k


def remove_duplicates_k(s: str, k: int) -> str:
    """Delete groups of ``k`` adjacent equal chars repeatedly. Fail-closed."""
    s, k = _req_s_k(s, k)
    stack: list[list] = []
    for ch in s:
        if stack and stack[-1][0] == ch:
            stack[-1][1] += 1
            if stack[-1][1] == k:
                stack.pop()
        else:
            stack.append([ch, 1])
    return "".join(ch * cnt for ch, cnt in stack)

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
    assert remove_duplicates_k("deeedbbcccbdaa", 3) == "aa"
    assert remove_duplicates_k("abcd", 2) == "abcd"
    assert remove_duplicates_k("pbbcggttciiippooaais", 2) == "ps"
    assert remove_duplicates_k("", 2) == ""
    try:
        remove_duplicates_k("aa", 1)
    except ValueError:
        pass
    else:
        raise AssertionError("k < 2 must raise ValueError")
    try:
        remove_duplicates_k(12, 2)
    except ValueError:
        pass
    else:
        raise AssertionError("non-string must raise ValueError")
    assert stdlib_only()
    print("stack_25 OK")


if __name__ == "__main__":
    main()
