"""Top n largest (AB-36), Simulated."""
from __future__ import annotations
import ast

VERSION = "topn.v1"
def top_n(xs: list, n: int) -> list:
    return sorted(xs, reverse=True)[:n]
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "re", "math", "base64", "hashlib", "hmac", "urllib", "collections", "itertools", "string", "json", "bisect"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert top_n([3, 1, 2], 2) == [3, 2]
    assert top_n([], 3) == []
    assert stdlib_only()
    print("topn OK")
if __name__ == "__main__": main()
