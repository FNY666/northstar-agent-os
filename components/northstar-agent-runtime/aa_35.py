"""Kth Smallest Util (D-U-035), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_35.v1"
def kth_smallest(xs: list, k: int):
    return sorted(xs)[k] if 0 <= k < len(xs) else None
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
    assert kth_smallest([3,1,2], 0) == 1
    assert kth_smallest([3,1,2], 2) == 3
    assert kth_smallest([], 0) is None
    assert stdlib_only()
    print("aa_35 OK")
if __name__ == "__main__": main()
