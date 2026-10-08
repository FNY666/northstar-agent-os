"""Pangram check. (sm2-19)."""
from __future__ import annotations
import ast
VERSION = "sm2-pangram.v1"

def is_pangram(s: str) -> bool:
    return set('abcdefghijklmnopqrstuvwxyz') <= set(s.lower())

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
    assert is_pangram('The quick brown fox jumps over the lazy dog')
    assert not is_pangram('hello')
    assert not is_pangram('')
    assert stdlib_only()

if __name__ == "__main__":
    main()
