"""Mode Util (D-U-018), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_18.v1"
def mode(xs: list):
    from collections import Counter
    return Counter(xs).most_common(1)[0][0] if xs else None
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
    assert mode([1,2,2,3]) == 2
    assert mode([]) is None
    assert mode([7]) == 7
    assert stdlib_only()
    print("aa_18 OK")
if __name__ == "__main__": main()
