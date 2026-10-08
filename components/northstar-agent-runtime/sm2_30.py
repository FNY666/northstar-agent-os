"""Repeat-join with separator. (sm2-30)."""
from __future__ import annotations
import ast
VERSION = "sm2-joinrep.v1"

def repeat_join(s: str, n: int, sep: str = ',') -> str:
    return sep.join([s] * n)

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
    assert repeat_join('ab', 3) == 'ab,ab,ab'
    assert repeat_join('x', 1, '-') == 'x'
    assert repeat_join('y', 0) == ""
    assert stdlib_only()

if __name__ == "__main__":
    main()
