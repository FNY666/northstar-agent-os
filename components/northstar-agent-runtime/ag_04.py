"""Running Mean, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_04.v1"
def rmean(xs: list) -> float:
    if not xs: raise ValueError("empty")
    return sum(xs) / len(xs)
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
    assert rmean([1,2,3]) == 2.0
    assert rmean([10]) == 10.0
    assert rmean([0,0,4,4]) == 2.0
    assert stdlib_only()
    print("ag_04 OK")
if __name__ == "__main__": main()
