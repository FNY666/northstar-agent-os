"""Group By, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_30.v1"
def groupby(xs: list, key) -> dict:
    out: dict = {}
    for x in xs: out.setdefault(key(x), []).append(x)
    return out
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "itertools", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert groupby([1,2,3,4], lambda x: x % 2) == {1:[1,3], 0:[2,4]}
    assert groupby([], str) == {}
    assert groupby(["a","bb"], len) == {1:["a"], 2:["bb"]}
    assert stdlib_only()
    print("ag_30 OK")
if __name__ == "__main__": main()
