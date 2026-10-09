"""Merge Dicts Util (D-U-027), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_27.v1"
def merge_dicts(*ds: dict) -> dict:
    out: dict = {}
    for d in ds:
        out.update(d)
    return out
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
    assert merge_dicts({"a":1},{"b":2}) == {"a":1,"b":2}
    assert merge_dicts() == {}
    assert merge_dicts({"a":1},{"a":2}) == {"a":2}
    assert stdlib_only()
    print("aa_27 OK")
if __name__ == "__main__": main()
