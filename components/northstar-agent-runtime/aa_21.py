"""Rotate Left Util (D-U-021), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_21.v1"
def rotate_left(xs: list, k: int) -> list:
    k = k % len(xs) if xs else 0
    return xs[k:] + xs[:k]
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert rotate_left([1,2,3,4], 1) == [2,3,4,1]
    assert rotate_left([], 3) == []
    assert rotate_left([1], 5) == [1]
    assert stdlib_only()
    print("aa_21 OK")
if __name__ == "__main__": main()
