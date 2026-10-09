"""Insert Sorted Util (D-U-033), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_33.v1"
def insert_sorted(xs: list, v) -> list:
    out = list(xs)
    for i, x in enumerate(out):
        if v <= x:
            out.insert(i, v); return out
    out.append(v); return out
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
    assert insert_sorted([1,3,5], 4) == [1,3,4,5]
    assert insert_sorted([], 2) == [2]
    assert insert_sorted([1,2], 0) == [0,1,2]
    assert stdlib_only()
    print("aa_33 OK")
if __name__ == "__main__": main()
