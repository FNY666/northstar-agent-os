"""Const Time Eq Util (D-U-046), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_46.v1"
def const_time_eq(a: bytes, b: bytes) -> bool:
    import hmac as _h
    return _h.compare_digest(a, b)
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
    assert const_time_eq(b"a", b"a")
    assert not const_time_eq(b"a", b"b")
    assert const_time_eq(b"", b"")
    assert stdlib_only()
    print("aa_46 OK")
if __name__ == "__main__": main()
