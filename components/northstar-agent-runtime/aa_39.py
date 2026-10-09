"""Moving Avg Util (D-U-039), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_39.v1"
def moving_avg(xs: list, n: int) -> list:
    return [sum(xs[i:i+n]) / n for i in range(len(xs) - n + 1)] if n > 0 else []
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
    assert moving_avg([1,2,3,4], 2) == [1.5,2.5,3.5]
    assert moving_avg([], 2) == []
    assert moving_avg([5], 1) == [5.0]
    assert stdlib_only()
    print("aa_39 OK")
if __name__ == "__main__": main()
