"""Base64 encode/decode (AB-20), Simulated."""
from __future__ import annotations
import ast
import base64
VERSION = "b64.v1"
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()
def b64d(s: str) -> bytes:
    return base64.b64decode(s)
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
    assert b64e(b"hi") == "aGk="
    assert b64d("aGk=") == b"hi"
    assert stdlib_only()
    print("b64 OK")
if __name__ == "__main__": main()
