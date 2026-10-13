"""Pad right to width. (sm2-24)."""
from __future__ import annotations
import ast
VERSION = "sm2-padr.v1"

def pad_right(s: str, n: int, ch: str = ' ') -> str:
    return s if len(s) >= n else s + ch * (n - len(s))

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
    assert pad_right('42', 5, '0') == '42000'
    assert pad_right('abc', 2) == 'abc'
    assert pad_right('', 3) == '   '
    assert stdlib_only()

if __name__ == "__main__":
    main()
