"""Sha256 Hex Util (D-U-043), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_43.v1"
def sha256_hex(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode('utf-8')).hexdigest()
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
    assert len(sha256_hex("x")) == 64
    assert sha256_hex("a") != sha256_hex("b")
    assert sha256_hex("") == sha256_hex("")
    assert stdlib_only()
    print("aa_43 OK")
if __name__ == "__main__": main()
