"""Isogram check (no repeated letters). (sm2-20)."""
from __future__ import annotations
import ast
VERSION = "sm2-isogram.v1"

def is_isogram(s: str) -> bool:
    t = s.lower()
    return len(set(t)) == len(t)

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
    assert is_isogram('abc')
    assert not is_isogram('aba')
    assert is_isogram('')
    assert stdlib_only()

if __name__ == "__main__":
    main()
