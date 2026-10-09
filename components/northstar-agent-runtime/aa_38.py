"""Zscore Cap Util (D-U-038), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_38.v1"
def zscore_cap(x: float, cap: float = 3.0) -> float:
    return max(-cap, min(cap, x))
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
    assert zscore_cap(5.0) == 3.0
    assert zscore_cap(-9.0) == -3.0
    assert zscore_cap(1.5) == 1.5
    assert stdlib_only()
    print("aa_38 OK")
if __name__ == "__main__": main()
