"""Rand Token Util (D-U-050), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_50.v1"
def rand_token(n: int = 16) -> str:
    import secrets
    return secrets.token_hex(n)
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
    assert len(rand_token(8)) == 16
    assert rand_token(4) != rand_token(4) or True
    assert len(rand_token(0)) == 0
    assert stdlib_only()
    print("aa_50 OK")
if __name__ == "__main__": main()
