"""Shortest word. (sm2-12)."""
from __future__ import annotations
import ast
VERSION = "sm2-shortest.v1"

def shortest_word(s: str) -> str:
    words = s.split()
    return min(words, key=len) if words else ''

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
    assert shortest_word('a bb ccc') == 'a'
    assert shortest_word('') == ''
    assert shortest_word('hi') == 'hi'
    assert stdlib_only()

if __name__ == "__main__":
    main()
