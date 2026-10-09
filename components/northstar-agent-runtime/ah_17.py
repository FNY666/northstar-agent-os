"""Hex Encode Bytes."""
from __future__ import annotations
import ast

VERSION = "ah_17.v1"
def hex_encode(b: bytes) -> str:
    return b.hex()
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
    assert hex_encode(b'abc') == '616263'
    assert hex_encode(b'') == ''
    assert stdlib_only()
    print("ah_17 OK")
if __name__ == "__main__": main()
