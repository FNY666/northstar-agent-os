"""Pairs Util (D-U-023), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_23.v1"
def pairs(xs: list) -> list:
    return [(xs[i], xs[i+1]) for i in range(0, len(xs) - 1, 2)]
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert pairs([1,2,3,4]) == [(1,2),(3,4)]
    assert pairs([1]) == []
    assert pairs([]) == []
    assert stdlib_only()
    print("aa_23 OK")
if __name__ == "__main__": main()
