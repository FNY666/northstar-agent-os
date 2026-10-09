"""Invert Dict Util (D-U-025), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_25.v1"
def invert_dict(d: dict) -> dict:
    out: dict = {}
    for k, v in d.items():
        out.setdefault(v, []).append(k)
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
    assert invert_dict({"a":1,"b":1}) == {1: ["a","b"]}
    assert invert_dict({}) == {}
    assert invert_dict({"x":2}) == {2: ["x"]}
    assert stdlib_only()
    print("aa_25 OK")
if __name__ == "__main__": main()
