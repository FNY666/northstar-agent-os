"""Sign Util (D-AC-006), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_06.v1"
def sign(n: float) -> int:
    return (n > 0) - (n < 0)
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
    assert sign(5) == 1
    assert sign(-5) == -1
    assert sign(0) == 0
    assert stdlib_only()
    print("ac_06 OK")
if __name__ == "__main__": main()
