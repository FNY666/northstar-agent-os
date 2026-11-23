"""Pad left to width. (sm2-23)."""
from __future__ import annotations
import ast
VERSION = "sm2-padl.v1"

def pad_left(s: str, n: int, ch: str = ' ') -> str:
    return s if len(s) >= n else ch * (n - len(s)) + s

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
    assert pad_left('42', 5, '0') == '00042'
    assert pad_left('abc', 2) == 'abc'
    assert pad_left('', 3) == '   '
    assert stdlib_only()

if __name__ == "__main__":
    main()
