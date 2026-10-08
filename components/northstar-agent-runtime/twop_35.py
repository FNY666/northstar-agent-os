"""backspace_compare (two-pointer), compare strings with '#' as backspace. IS: exact equality after applying backspaces, using O(1) extra space two-pointer from the end. IS NOT: a stack-based or regex-based text editor; '#' has no escape form."""
from __future__ import annotations

import ast

VERSION = "twop-35.v1"


def _prev_valid(text: str, i: int) -> int:
    skip = 0
    while i >= 0:
        if text[i] == "#":
            skip += 1
        elif skip:
            skip -= 1
        else:
            break
        i -= 1
    return i


def backspace_compare(s: str, t: str) -> bool:
    if not isinstance(s, str) or not isinstance(t, str):
        raise ValueError("s and t must be strings")
    i, j = len(s) - 1, len(t) - 1
    while i >= 0 or j >= 0:
        i = _prev_valid(s, i)
        j = _prev_valid(t, j)
        if i < 0 or j < 0:
            return i == -1 and j == -1
        if s[i] != t[j]:
            return False
        i -= 1
        j -= 1
    return True


def stdlib_only() -> bool:
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text())
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
    assert backspace_compare("ab#c", "ad#c") is True
    assert backspace_compare("ab##", "c#d#") is True  # both reduce to empty
    assert backspace_compare("a#c", "b") is False
    assert backspace_compare("###", "") is True  # edge: only backspaces
    assert backspace_compare("a##c", "#a#c") is True
    try:
        backspace_compare("ab#c", None)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("non-string t must raise ValueError")
    assert stdlib_only()
    print("twop_35 OK")


if __name__ == "__main__":
    main()
