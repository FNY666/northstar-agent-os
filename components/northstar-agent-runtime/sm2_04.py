"""Count consonants in a string. (sm2-04)."""
from __future__ import annotations
import ast
VERSION = "sm2-consonants.v1"

def count_consonants(s: str) -> int:
    return sum(1 for c in s.lower() if c.isalpha() and c not in 'aeiou')

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
    assert count_consonants('hello') == 3
    assert count_consonants('aeiou') == 0
    assert count_consonants('') == 0
    assert stdlib_only()

if __name__ == "__main__":
    main()
