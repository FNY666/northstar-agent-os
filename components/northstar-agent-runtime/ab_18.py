"""ROT13 cipher (AB-18), Simulated."""
from __future__ import annotations
import ast

VERSION = "rot13.v1"
def rot13(s: str) -> str:
    import codecs
    return codecs.encode(s, "rot_13")
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "re", "math", "base64", "hashlib", "hmac", "urllib", "collections", "itertools", "string", "json", "bisect", "codecs"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert rot13("hello") == "uryyb"
    assert rot13(rot13("abc")) == "abc"
    assert stdlib_only()
    print("rot13 OK")
if __name__ == "__main__": main()
