"""Mean Util (D-U-016), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_16.v1"
def mean(xs: list) -> float:
    return sum(xs) / len(xs) if xs else 0.0
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
    assert mean([1,2,3]) == 2.0
    assert mean([]) == 0.0
    assert mean([5]) == 5.0
    assert stdlib_only()
    print("aa_16 OK")
if __name__ == "__main__": main()
