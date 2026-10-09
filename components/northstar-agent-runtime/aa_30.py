"""Top N Util (D-U-030), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_30.v1"
def top_n(d: dict, n: int) -> list:
    return sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]
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
    assert top_n({"a":1,"b":3,"c":2}, 2) == [("b",3),("c",2)]
    assert top_n({}, 5) == []
    assert top_n({"a":1}, 9) == [("a",1)]
    assert stdlib_only()
    print("aa_30 OK")
if __name__ == "__main__": main()
