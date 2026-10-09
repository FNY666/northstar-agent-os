"""Binary search index (AB-49), Simulated."""
from __future__ import annotations
import ast
import bisect
VERSION = "bsearch.v1"
def bsearch(xs: list, x) -> int:
    i = bisect.bisect_left(xs, x)
    return i if i < len(xs) and xs[i] == x else -1
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
    assert bsearch([1, 2, 3], 2) == 1
    assert bsearch([1, 2, 3], 5) == -1
    assert stdlib_only()
    print("bsearch OK")
if __name__ == "__main__": main()
