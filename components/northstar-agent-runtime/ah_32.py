"""Join URL-ish Segments."""
from __future__ import annotations
import ast

VERSION = "ah_32.v1"
def join_segments(*segs: str) -> str:
    return '/'.join(s.strip('/') for s in segs if s.strip('/'))
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
    assert join_segments('/a/', '/b/', 'c') == 'a/b/c'
    assert join_segments('x') == 'x'
    assert join_segments() == ''
    assert stdlib_only()
    print("ah_32 OK")
if __name__ == "__main__": main()
