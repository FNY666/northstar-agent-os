"""SHA256 Hex, Simulated."""
from __future__ import annotations
import ast
import hashlib
VERSION = "ag_08.v1"
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
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
    assert len(sha256_hex(bytes([120]))) == 64
    assert sha256_hex(bytes([97])) != sha256_hex(bytes([98]))
    assert sha256_hex(bytes()) == hashlib.sha256(bytes()).hexdigest()
    assert stdlib_only()
    print("ag_08 OK")
if __name__ == "__main__": main()
