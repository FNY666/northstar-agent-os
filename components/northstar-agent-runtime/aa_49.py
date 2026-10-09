"""Is Hex Util (D-U-049), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_49.v1"
def is_hex(s: str) -> bool:
    return len(s) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in s)
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
    assert is_hex("ff00")
    assert not is_hex("fg")
    assert is_hex("")
    assert stdlib_only()
    print("aa_49 OK")
if __name__ == "__main__": main()
