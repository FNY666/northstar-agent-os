"""Adjacent differences (AB-44), Simulated."""
from __future__ import annotations
import ast

VERSION = "diffs.v1"
def diffs(xs: list) -> list:
    return [b - a for a, b in zip(xs, xs[1:])]
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
    assert diffs([1, 3, 2]) == [2, -1]
    assert diffs([5]) == []
    assert stdlib_only()
    print("diffs OK")
if __name__ == "__main__": main()
