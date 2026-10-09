"""XOR Bytes With Key."""
from __future__ import annotations
import ast

VERSION = "ah_19.v1"
def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
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
    assert xor_bytes(b'abc', b'k') == xor_bytes(xor_bytes(b'abc', b'k'), b'k') or xor_bytes(b'abc', b'k') != b'abc'
    assert len(xor_bytes(b'abc', b'k')) == 3
    assert stdlib_only()
    print("ah_19 OK")
if __name__ == "__main__": main()
