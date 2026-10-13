"""Anagram check. (sm2-13)."""
from __future__ import annotations
import ast
VERSION = "sm2-anagram.v1"

def is_anagram(a: str, b: str) -> bool:
    return sorted(a.lower()) == sorted(b.lower())

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
    assert is_anagram('listen', 'silent')
    assert not is_anagram('hello', 'world')
    assert is_anagram('', '')
    assert stdlib_only()

if __name__ == "__main__":
    main()
