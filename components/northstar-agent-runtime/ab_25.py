"""HMAC-SHA256 (AB-25), Simulated."""
from __future__ import annotations
import ast
import hmac, hashlib
VERSION = "hmac.v1"
def hmac_sha256(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
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
    assert len(hmac_sha256(b"k", b"m")) == 64
    assert hmac_sha256(b"a", b"b") != hmac_sha256(b"a", b"c")
    assert stdlib_only()
    print("hmac OK")
if __name__ == "__main__": main()
