"""Moving Average, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_15.v1"
def movavg(xs: list, w: int) -> list:
    if w <= 0 or w > len(xs): raise ValueError("bad window")
    return [sum(xs[i:i+w]) / w for i in range(len(xs) - w + 1)]
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
    assert movavg([1,2,3,4], 2) == [1.5, 2.5, 3.5]
    assert movavg([5,5,5], 3) == [5.0]
    assert movavg([1,3], 1) == [1.0, 3.0]
    assert stdlib_only()
    print("ag_15 OK")
if __name__ == "__main__": main()
