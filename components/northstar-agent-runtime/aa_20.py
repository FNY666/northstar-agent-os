"""Running Total Util (D-U-020), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_20.v1"
def running_total(xs: list) -> list:
    out, t = [], 0
    for x in xs:
        t += x; out.append(t)
    return out
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
    assert running_total([1,2,3]) == [1,3,6]
    assert running_total([]) == []
    assert running_total([5]) == [5]
    assert stdlib_only()
    print("aa_20 OK")
if __name__ == "__main__": main()
