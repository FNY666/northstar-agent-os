"""Capitalize each word. (sm2-08)."""
from __future__ import annotations
import ast
VERSION = "sm2-title.v1"

def title_words(s: str) -> str:
    return ' '.join(w[:1].upper() + w[1:] for w in s.split(' '))

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
    assert title_words('hello world') == 'Hello World'
    assert title_words('') == ''
    assert title_words('a') == 'A'
    assert stdlib_only()

if __name__ == "__main__":
    main()
