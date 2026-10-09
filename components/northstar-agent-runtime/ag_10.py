"""Bounded Queue, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_10.v1"
def bqueue_add(q: list, item: object, cap: int) -> list:
    q = q + [item]
    return q[-cap:] if cap > 0 else []
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
    assert bqueue_add([1,2], 3, 2) == [2,3]
    assert bqueue_add([], 1, 3) == [1]
    assert bqueue_add([1], 2, 1) == [2]
    assert stdlib_only()
    print("ag_10 OK")
if __name__ == "__main__": main()
