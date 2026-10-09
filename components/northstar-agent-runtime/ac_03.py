"""Square Util (D-AC-003), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_03.v1"
def square(n: float) -> float:
    return n * n
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
    assert square(5) == 25
    assert square(-3) == 9
    assert square(0) == 0
    assert stdlib_only()
    print("ac_03 OK")
if __name__ == "__main__": main()
