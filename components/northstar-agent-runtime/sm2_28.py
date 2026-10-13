"""Swap letter case. (sm2-28)."""
from __future__ import annotations
import ast
VERSION = "sm2-swapcase.v1"

def swap_case(s: str) -> str:
    return ''.join(c.lower() if c.isupper() else c.upper() for c in s)

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
    assert swap_case('aBc') == 'AbC'
    assert swap_case('') == ''
    assert swap_case('123') == '123'
    assert stdlib_only()

if __name__ == "__main__":
    main()
