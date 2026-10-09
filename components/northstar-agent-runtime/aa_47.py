"""To Hex Util (D-U-047), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_47.v1"
def to_hex(data: bytes) -> str:
    return data.hex()
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
    assert to_hex(b"\xff") == "ff"
    assert to_hex(b"") == ""
    assert to_hex(b"AB") == "4142"
    assert stdlib_only()
    print("aa_47 OK")
if __name__ == "__main__": main()
