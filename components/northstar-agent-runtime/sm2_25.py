"""Strip punctuation. (sm2-25)."""
from __future__ import annotations
import ast
VERSION = "sm2-nopunct.v1"

def strip_punct(s: str) -> str:
    return ''.join(c for c in s if c.isalnum() or c.isspace())

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
    assert strip_punct('hi, you!') == 'hi you'
    assert strip_punct('abc') == 'abc'
    assert strip_punct('') == ''
    assert stdlib_only()

if __name__ == "__main__":
    main()
