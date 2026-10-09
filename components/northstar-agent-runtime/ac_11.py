"""Double Util (D-AC-011), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_11.v1"
def double(n: float) -> float:
    return 2 * n
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
    assert double(4) == 8
    assert double(-3) == -6
    assert double(0) == 0
    assert stdlib_only()
    print("ac_11 OK")
if __name__ == "__main__": main()
