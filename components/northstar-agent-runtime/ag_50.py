"""XOR Checksum, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_50.v1"
def xor_sum(data: bytes) -> int:
    r = 0
    for b in data: r ^= b
    return r
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
    assert xor_sum(bytes()) == 0
    assert xor_sum(bytes([1, 2])) == 0x03
    assert xor_sum(bytes([97, 97])) == 0
    assert stdlib_only()
    print("ag_50 OK")
if __name__ == "__main__": main()
