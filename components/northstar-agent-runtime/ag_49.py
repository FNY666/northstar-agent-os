"""Rolling Hash, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_49.v1"
def rollhash(s: str, base: int = 31, mod: int = 2**61 - 1) -> int:
    h = 0
    for c in s: h = (h * base + ord(c)) % mod
    return h
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
    assert rollhash("") == 0
    assert rollhash("a") == ord("a")
    assert rollhash("ab") != rollhash("ba")
    assert stdlib_only()
    print("ag_49 OK")
if __name__ == "__main__": main()
