"""Base64URL Codec, Simulated."""
from __future__ import annotations
import ast
import base64
VERSION = "ag_07.v1"
def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")
def b64d(tok: str) -> bytes:
    return base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4))
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "itertools", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert b64d(b64e(bytes([104, 101, 108, 108, 111]))) == bytes([104, 101, 108, 108, 111])
    assert b64e(b"") == ""
    assert b64d(b64e(bytes([0, 255]))) == bytes([0, 255])
    assert stdlib_only()
    print("ag_07 OK")
if __name__ == "__main__": main()
