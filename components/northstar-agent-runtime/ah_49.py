"""Simple Checksum Mod."""
from __future__ import annotations
import ast

VERSION = "ah_49.v1"
def simple_checksum(b: bytes, mod: int = 256) -> int:
    return sum(b) % mod
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
    assert simple_checksum(b'abc') == (97 + 98 + 99) % 256
    assert simple_checksum(b'', 16) == 0
    assert stdlib_only()
    print("ah_49 OK")
if __name__ == "__main__": main()
