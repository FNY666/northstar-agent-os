"""Range Of Util (D-U-036), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_36.v1"
def range_of(xs: list):
    return (min(xs), max(xs)) if xs else (None, None)
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
    assert range_of([3,1,2]) == (1, 3)
    assert range_of([]) == (None, None)
    assert range_of([7]) == (7, 7)
    assert stdlib_only()
    print("aa_36 OK")
if __name__ == "__main__": main()
