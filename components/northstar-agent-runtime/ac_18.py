"""Digit Sum Util (D-AC-018), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_18.v1"
def digit_sum(n: int) -> int:
    return sum(int(d) for d in str(abs(n)))
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
    assert digit_sum(123) == 6
    assert digit_sum(-45) == 9
    assert digit_sum(0) == 0
    assert stdlib_only()
    print("ac_18 OK")
if __name__ == "__main__": main()
