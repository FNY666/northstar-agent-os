"""Sliding window sums (AB-42), Simulated."""
from __future__ import annotations
import ast

VERSION = "winsum.v1"
def window_sums(xs: list, k: int) -> list:
    return [sum(xs[i:i + k]) for i in range(len(xs) - k + 1)]
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
    assert window_sums([1, 2, 3], 2) == [3, 5]
    assert window_sums([5], 1) == [5]
    assert stdlib_only()
    print("winsum OK")
if __name__ == "__main__": main()
