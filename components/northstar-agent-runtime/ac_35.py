"""Harmonic Util (D-AC-035), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_35.v1"
def harmonic(n: int) -> float:
    return sum(1.0 / i for i in range(1, n + 1))
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
    assert harmonic(1) == 1.0
    assert abs(harmonic(2) - 1.5) < 1e-9
    assert harmonic(0) == 0
    assert stdlib_only()
    print("ac_35 OK")
if __name__ == "__main__": main()
