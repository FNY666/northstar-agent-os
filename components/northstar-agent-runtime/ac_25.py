"""Perfect Square Util (D-AC-025), Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ac_25.v1"
def is_square(n: int) -> bool:
    r = math.isqrt(n)
    return r * r == n
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
    assert is_square(16)
    assert is_square(0)
    assert not is_square(15)
    assert stdlib_only()
    print("ac_25 OK")
if __name__ == "__main__": main()
