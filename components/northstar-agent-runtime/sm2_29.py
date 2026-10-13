"""Remove vowels. (sm2-29)."""
from __future__ import annotations
import ast
VERSION = "sm2-novowel.v1"

def remove_vowels(s: str) -> str:
    return ''.join(c for c in s if c.lower() not in 'aeiou')

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
    assert remove_vowels('hello') == 'hll'
    assert remove_vowels('AEIOU') == ''
    assert remove_vowels('rhythm') == 'rhythm'
    assert stdlib_only()

if __name__ == "__main__":
    main()
