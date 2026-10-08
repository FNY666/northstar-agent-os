"""Check string rotation. (sm2-16)."""
from __future__ import annotations
import ast
VERSION = "sm2-rotation.v1"

def is_rotation(a: str, b: str) -> bool:
    return len(a) == len(b) and b in (a + a)

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
    assert is_rotation('abcd', 'cdab')
    assert not is_rotation('abcd', 'acbd')
    assert is_rotation('', '')
    assert stdlib_only()

if __name__ == "__main__":
    main()
