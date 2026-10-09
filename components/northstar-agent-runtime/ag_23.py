"""One-Hot Encode, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_23.v1"
def onehot(idx: int, n: int) -> list:
    if not 0 <= idx < n: raise ValueError("idx")
    return [1.0 if i == idx else 0.0 for i in range(n)]
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
    assert onehot(1, 3) == [0.0, 1.0, 0.0]
    assert onehot(0, 1) == [1.0]
    assert sum(onehot(2, 4)) == 1.0
    assert stdlib_only()
    print("ag_23 OK")
if __name__ == "__main__": main()
