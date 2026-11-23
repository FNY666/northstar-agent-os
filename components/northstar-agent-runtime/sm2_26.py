"""Count substring occurrences (overlap). (sm2-26)."""
from __future__ import annotations
import ast
VERSION = "sm2-countsub.v1"

def count_sub(s: str, sub: str) -> int:
    return sum(s[i:i+len(sub)] == sub for i in range(len(s) - len(sub) + 1)) if sub else 0

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True

def main() -> None:
    assert count_sub('aaa', 'aa') == 2
    assert count_sub('hello', 'z') == 0
    assert count_sub('abc', '') == 0
    assert stdlib_only()

if __name__ == "__main__":
    main()
