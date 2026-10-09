"""Repeat Fill Sequence."""
from __future__ import annotations
import ast

VERSION = "ah_22.v1"
def repeat_fill(value, n: int) -> list:
    return [value] * max(0, n)
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "itertools", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert repeat_fill('x', 3) == ['x', 'x', 'x']
    assert repeat_fill(1, 0) == []
    assert stdlib_only()
    print("ah_22 OK")
if __name__ == "__main__": main()
