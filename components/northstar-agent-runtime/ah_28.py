"""Strip Prefix."""
from __future__ import annotations
import ast

VERSION = "ah_28.v1"
def strip_prefix(s: str, prefix: str) -> str:
    return s[len(prefix):] if s.startswith(prefix) else s
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
    assert strip_prefix('/a/b', '/a') == '/b'
    assert strip_prefix('abc', 'x') == 'abc'
    assert stdlib_only()
    print("ah_28 OK")
if __name__ == "__main__": main()
