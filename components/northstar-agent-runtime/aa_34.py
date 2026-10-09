"""Merge Sorted Util (D-U-034), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_34.v1"
def merge_sorted(a: list, b: list) -> list:
    i = j = 0
    out = []
    while i < len(a) and j < len(b):
        out.append(a[i] if a[i] <= b[j] else b[j]); i, j = (i+1, j) if a[i] <= b[j] else (i, j+1)
    return out + a[i:] + b[j:]
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
    assert merge_sorted([1,3],[2,4]) == [1,2,3,4]
    assert merge_sorted([], [1]) == [1]
    assert merge_sorted([2], []) == [2]
    assert stdlib_only()
    print("aa_34 OK")
if __name__ == "__main__": main()
