"""Backtracking: remove the minimum invalid parentheses, all results.

IS: given a string with '(' , ')' and other chars, finds every distinct
string obtainable by deleting the fewest parentheses that is a balanced
parentheses string (other chars untouched), via precomputed removal
counts plus DFS. IS NOT: a parser or linter - it knows nothing about
code semantics, and it returns strings, not edit scripts or positions.
"""

import ast
from typing import List, Optional

VERSION = "backtrack_26.v1"


def remove_invalid_parentheses(s: str) -> List[str]:
    """All valid strings after the minimum number of paren removals."""
    left_remove = right_remove = 0
    for ch in s:
        if ch == "(":
            left_remove += 1
        elif ch == ")":
            if left_remove > 0:
                left_remove -= 1
            else:
                right_remove += 1
    results = set()

    def dfs(i: int, l: int, r: int, open_: int, path: List[str]) -> None:
        if i == len(s):
            if l == 0 and r == 0 and open_ == 0:
                results.add("".join(path))
            return
        ch = s[i]
        if ch == "(":
            if l > 0:
                dfs(i + 1, l - 1, r, open_, path)
            path.append(ch)
            dfs(i + 1, l, r, open_ + 1, path)
            path.pop()
        elif ch == ")":
            if r > 0:
                dfs(i + 1, l, r - 1, open_, path)
            if open_ > 0:
                path.append(ch)
                dfs(i + 1, l, r, open_ - 1, path)
                path.pop()
        else:
            path.append(ch)
            dfs(i + 1, l, r, open_, path)
            path.pop()

    dfs(0, left_remove, right_remove, 0, [])
    return sorted(results)


def stdlib_only(path: Optional[str] = None) -> bool:
    """Parse this file with ast; True iff every import is stdlib-allowed."""
    allowed = {"typing", "dataclasses", "itertools", "ast"}
    with open(path or __file__, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod and mod not in allowed:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert remove_invalid_parentheses("()())()") == ["(())()", "()()()"]
    assert remove_invalid_parentheses("(a)())()") == ["(a())()", "(a)()()"]
    assert remove_invalid_parentheses(")(") == [""]
    assert remove_invalid_parentheses("()") == ["()"]
    assert remove_invalid_parentheses("((()") == ["()"]
    print("backtrack_26 OK")


if __name__ == "__main__":
    main()
