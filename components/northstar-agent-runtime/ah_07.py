"""Clamp Index Into List."""
from __future__ import annotations
import ast

VERSION = "ah_07.v1"
def clamp_index(i: int, n: int) -> int:
    return max(0, min(n - 1, i)) if n > 0 else 0
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
    assert clamp_index(5, 3) == 2
    assert clamp_index(-2, 3) == 0
    assert clamp_index(1, 0) == 0
    assert stdlib_only()
    print("ah_07 OK")
if __name__ == "__main__": main()
