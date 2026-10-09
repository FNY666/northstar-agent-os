"""Cumsum Reset Util (D-U-040), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_40.v1"
def cumsum_reset(xs: list, reset_at: int) -> list:
    out, t = [], 0
    for x in xs:
        t = 0 if t + x > reset_at else t + x
        out.append(t)
    return out
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
    assert cumsum_reset([1,2,8], 9) == [1,3,0]
    assert cumsum_reset([], 5) == []
    assert cumsum_reset([1,1], 9) == [1,2]
    assert stdlib_only()
    print("aa_40 OK")
if __name__ == "__main__": main()
