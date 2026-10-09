"""Digital Root Util (D-AC-032), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_32.v1"
def digital_root(n: int) -> int:
    return 1 + (n - 1) % 9 if n else 0
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
    assert digital_root(38) == 2
    assert digital_root(9) == 9
    assert digital_root(0) == 0
    assert stdlib_only()
    print("ac_32 OK")
if __name__ == "__main__": main()
