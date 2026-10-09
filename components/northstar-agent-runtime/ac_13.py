"""Percent Util (D-AC-013), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_13.v1"
def pct(part: float, whole: float) -> float:
    return 100.0 * part / whole
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
    assert pct(1, 4) == 25.0
    assert pct(1, 2) == 50.0
    assert pct(0, 5) == 0.0
    assert stdlib_only()
    print("ac_13 OK")
if __name__ == "__main__": main()
