"""Deep Get, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_26.v1"
def dget(d: dict, path: str, default: object = None) -> object:
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur: return default
        cur = cur[p]
    return cur
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
    assert dget({"a":{"b":1}}, "a.b") == 1
    assert dget({"a":{}}, "a.b.c", 9) == 9
    assert dget({}, "x") is None
    assert stdlib_only()
    print("ag_26 OK")
if __name__ == "__main__": main()
