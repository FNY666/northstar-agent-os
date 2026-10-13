"""Truncate with ellipsis. (sm2-22)."""
from __future__ import annotations
import ast
VERSION = "sm2-trunc.v1"

def truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:max(n - 3, 0)] + '...'

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
    assert truncate('hello world', 8) == 'hello...'
    assert truncate('hi', 8) == 'hi'
    assert truncate('abcdef', 6) == 'abcdef'
    assert stdlib_only()

if __name__ == "__main__":
    main()
