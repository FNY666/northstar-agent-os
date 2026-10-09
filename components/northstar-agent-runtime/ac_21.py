"""Palindrome Num Util (D-AC-021), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_21.v1"
def is_pal_num(n: int) -> bool:
    s = str(n)
    return s == s[::-1]
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "math", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert is_pal_num(121)
    assert is_pal_num(5)
    assert not is_pal_num(123)
    assert stdlib_only()
    print("ac_21 OK")
if __name__ == "__main__": main()
