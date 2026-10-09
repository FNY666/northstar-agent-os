"""Zip Pad Util (D-U-022), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_22.v1"
def zip_pad(a: list, b: list, fill=None) -> list:
    n = max(len(a), len(b))
    return [(a[i] if i < len(a) else fill, b[i] if i < len(b) else fill) for i in range(n)]
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
    assert zip_pad([1,2],[3]) == [(1,3),(2,None)]
    assert zip_pad([],[]) == []
    assert zip_pad([1],[2,3],0) == [(1,2),(0,3)]
    assert stdlib_only()
    print("aa_22 OK")
if __name__ == "__main__": main()
