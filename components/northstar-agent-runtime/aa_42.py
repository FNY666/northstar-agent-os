"""Decode B64Ish Util (D-U-042), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_42.v1"
def decode_b64ish(s: str) -> bytes:
    import base64
    return base64.b64decode(s.encode('ascii'))
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
    assert decode_b64ish("aGk=") == b"hi"
    assert decode_b64ish("") == b""
    assert decode_b64ish("YWJj") == b"abc"
    assert stdlib_only()
    print("aa_42 OK")
if __name__ == "__main__": main()
