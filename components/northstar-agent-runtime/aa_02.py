"""Chunk Util (D-U-002), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_02.v1"
def chunk(xs: list, n: int) -> list:
    return [xs[i:i+n] for i in range(0, len(xs), n)]
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
    assert chunk([1,2,3,4,5], 2) == [[1,2],[3,4],[5]]
    assert chunk([], 3) == []
    assert chunk([1], 5) == [[1]]
    assert stdlib_only()
    print("aa_02 OK")
if __name__ == "__main__": main()
