"""MD5 hex digest (AB-23), Simulated."""
from __future__ import annotations
import ast
import hashlib
VERSION = "md5.v1"
def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()
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
    assert md5("") == "d41d8cd98f00b204e9800998ecf8427e"
    assert len(md5("x")) == 32
    assert stdlib_only()
    print("md5 OK")
if __name__ == "__main__": main()
