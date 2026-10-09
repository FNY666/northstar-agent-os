"""Xor Bytes Util (D-U-045), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_45.v1"
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
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
    assert xor_bytes(b"\x01\x02", b"\x03\x04") == b"\x02\x06"
    assert xor_bytes(b"", b"") == b""
    assert xor_bytes(b"a", b"a") == b"\x00"
    assert stdlib_only()
    print("aa_45 OK")
if __name__ == "__main__": main()
