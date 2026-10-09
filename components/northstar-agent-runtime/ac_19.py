"""Digit Count Util (D-AC-019), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_19.v1"
def digit_count(n: int) -> int:
    return len(str(abs(n)))
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
    assert digit_count(123) == 3
    assert digit_count(0) == 1
    assert digit_count(-9876) == 4
    assert stdlib_only()
    print("ac_19 OK")
if __name__ == "__main__": main()
