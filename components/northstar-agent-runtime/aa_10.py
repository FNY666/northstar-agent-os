"""Slugify Util (D-U-010), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_10.v1"
def slugify(s: str) -> str:
    t = ''.join(c.lower() if c.isalnum() else '-' for c in s)
    return '-'.join(p for p in t.split('-') if p)
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
    assert slugify("Hello World!") == "hello-world"
    assert slugify("a--b") == "a-b"
    assert slugify("") == ""
    assert stdlib_only()
    print("aa_10 OK")
if __name__ == "__main__": main()
