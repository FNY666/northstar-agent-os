"""Count words. (sm2-10)."""
from __future__ import annotations
import ast
VERSION = "sm2-wordcount.v1"

def word_count(s: str) -> int:
    return len(s.split())

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
    assert word_count('hello world') == 2
    assert word_count('   ') == 0
    assert word_count('one') == 1
    assert stdlib_only()

if __name__ == "__main__":
    main()
