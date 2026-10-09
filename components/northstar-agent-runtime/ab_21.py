"""Hex encode/decode (AB-21), Simulated."""
from __future__ import annotations
import ast

VERSION = "hexc.v1"
def hexe(b: bytes) -> str:
    return b.hex()
def hexd(s: str) -> bytes:
    return bytes.fromhex(s)
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
    assert hexe(b"\xff") == "ff"
    assert hexd("ff") == b"\xff"
    assert stdlib_only()
    print("hexc OK")
if __name__ == "__main__": main()
