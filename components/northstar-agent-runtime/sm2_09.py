"""Remove all whitespace. (sm2-09)."""
from __future__ import annotations
import ast
VERSION = "sm2-nospace.v1"

def remove_whitespace(s: str) -> str:
    return ''.join(s.split())

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
    assert remove_whitespace('a b c') == 'abc'
    assert remove_whitespace('  x\ty\n') == 'xy'
    assert remove_whitespace('') == ''
    assert stdlib_only()

if __name__ == "__main__":
    main()
