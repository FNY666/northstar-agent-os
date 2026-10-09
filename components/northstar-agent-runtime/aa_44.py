"""Hmac Hex Util (D-U-044), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_44.v1"
def hmac_hex(key: bytes, msg: bytes) -> str:
    import hmac as _h, hashlib as _hl
    return _h.new(key, msg, _hl.sha256).hexdigest()
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
    assert len(hmac_hex(b"k", b"m")) == 64
    assert hmac_hex(b"k", b"m") == hmac_hex(b"k", b"m")
    assert hmac_hex(b"k1", b"m") != hmac_hex(b"k2", b"m")
    assert stdlib_only()
    print("aa_44 OK")
if __name__ == "__main__": main()
