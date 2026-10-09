"""Binary Search Util (D-U-032), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_32.v1"
def binary_search(xs: list, target) -> int:
    lo, hi = 0, len(xs)
    while lo < hi:
        m = (lo + hi) // 2
        if xs[m] < target: lo = m + 1
        else: hi = m
    return lo if lo < len(xs) and xs[lo] == target else -1
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
    assert binary_search([1,2,3,4], 3) == 2
    assert binary_search([1,2,3], 9) == -1
    assert binary_search([], 1) == -1
    assert stdlib_only()
    print("aa_32 OK")
if __name__ == "__main__": main()
