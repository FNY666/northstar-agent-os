"""Backtracking: Generate all balanced parentheses for n pairs.

Builds all strings of n '(' and n ')' that are correctly balanced by adding
'(' while open < n and ')' while close < open (prefix-validity pruning).

IS: the full Catalan(n) set of well-formed parenthesis strings.
IS NOT: a validator of arbitrary bracket types; NOT a duplicate-suppressing DP.
"""

from typing import List
import ast

VERSION = "backtrack_09.v1"


def generate_parentheses(n: int) -> List[str]:
    result: List[str] = []

    def backtrack(s: str, open_count: int, close_count: int) -> None:
        if len(s) == 2 * n:
            result.append(s)
            return
        if open_count < n:
            backtrack(s + "(", open_count + 1, close_count)
        if close_count < open_count:
            backtrack(s + ")", open_count, close_count + 1)

    backtrack("", 0, 0)
    return result


def stdlib_only() -> bool:
    allowed = {"typing", "ast"}
    with open(__file__) as f:
        tree = ast.parse(f.read())
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
    p3 = generate_parentheses(3)
    assert len(p3) == 5
    assert sorted(p3) == sorted(["((()))", "(()())", "(())()", "()(())", "()()()"])
    assert generate_parentheses(1) == ["()"]
    assert generate_parentheses(0) == [""]
    assert len(generate_parentheses(4)) == 14
    assert stdlib_only()
    print("backtrack_09 OK")


if __name__ == "__main__":
    main()
