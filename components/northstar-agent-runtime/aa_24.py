"""Group By Len Util (D-U-024), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_24.v1"
def group_by_len(words: list) -> dict:
    out: dict = {}
    for w in words:
        out.setdefault(len(w), []).append(w)
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
    assert group_by_len(["a","bb","c"]) == {1: ["a","c"], 2: ["bb"]}
    assert group_by_len([]) == {}
    assert len(group_by_len(["x"])) == 1
    assert stdlib_only()
    print("aa_24 OK")
if __name__ == "__main__": main()
