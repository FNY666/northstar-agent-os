"""Range Len Util (D-AC-050), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_50.v1"
def range_len(lo: float, hi: float) -> float:
    return max(0.0, hi - lo)
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
    assert range_len(2, 8) == 6.0
    assert range_len(8, 2) == 0.0
    assert range_len(5, 5) == 0.0
    assert stdlib_only()
    print("ac_50 OK")
if __name__ == "__main__": main()
