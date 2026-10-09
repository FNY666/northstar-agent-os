"""Deep Get Util (D-U-026), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_26.v1"
def deep_get(d: dict, path: str, default=None):
    cur = d
    for part in path.split('.'):
        cur = cur.get(part) if isinstance(cur, dict) else None
        if cur is None: return default
    return cur
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
    assert deep_get({"a":{"b":1}}, "a.b") == 1
    assert deep_get({}, "x") is None
    assert deep_get({"a":1}, "a.b.c", 9) == 9
    assert stdlib_only()
    print("aa_26 OK")
if __name__ == "__main__": main()
