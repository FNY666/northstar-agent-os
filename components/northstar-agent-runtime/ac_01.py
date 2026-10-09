"""Even Check Util (D-AC-001), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_01.v1"
def is_even(n: int) -> bool:
    return n % 2 == 0
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
    assert is_even(4)
    assert is_even(0)
    assert not is_even(7)
    assert stdlib_only()
    print("ac_01 OK")
if __name__ == "__main__": main()
