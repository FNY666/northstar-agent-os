"""Arithmetic mean (AB-14), Simulated."""
from __future__ import annotations
import ast

VERSION = "mean.v1"
def mean(xs: list) -> float:
    return sum(xs) / len(xs)
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
    assert mean([1, 2, 3]) == 2.0
    assert mean([5]) == 5.0
    assert stdlib_only()
    print("mean OK")
if __name__ == "__main__": main()
