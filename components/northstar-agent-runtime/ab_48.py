"""Non-decreasing check (AB-48), Simulated."""
from __future__ import annotations
import ast

VERSION = "issorted.v1"
def is_sorted(xs: list) -> bool:
    return all(a <= b for a, b in zip(xs, xs[1:]))
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
    assert is_sorted([1, 2, 2])
    assert not is_sorted([2, 1])
    assert is_sorted([])
    assert stdlib_only()
    print("issorted OK")
if __name__ == "__main__": main()
