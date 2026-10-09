"""Encode B64Ish Util (D-U-041), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_41.v1"
def encode_b64ish(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode('ascii')
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
    assert encode_b64ish(b"hi") == "aGk="
    assert encode_b64ish(b"") == ""
    assert encode_b64ish(b"abc") == "YWJj"
    assert stdlib_only()
    print("aa_41 OK")
if __name__ == "__main__": main()
