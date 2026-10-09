"""Symmetric difference (AB-47), Simulated."""
from __future__ import annotations
import ast

VERSION = "symdiff.v1"
def symdiff(a: list, b: list) -> list:
    sa, sb = set(a), set(b)
    return [x for x in a if x not in sb] + [x for x in b if x not in sa]
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
    assert symdiff([1, 2], [2, 3]) == [1, 3]
    assert symdiff([], []) == []
    assert stdlib_only()
    print("symdiff OK")
if __name__ == "__main__": main()
