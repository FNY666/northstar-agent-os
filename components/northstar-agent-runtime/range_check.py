"""Range checks (D-IN-030), Simulated."""
from __future__ import annotations
import ast
VERSION = "range-check.v1"
def check_range(v: float, min_v: float, max_v: float) -> bool:
    return min_v <= v <= max_v
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert check_range(5, 0, 10)
    assert not check_range(15, 0, 10)
    assert stdlib_only()
    print("range-check OK")
if __name__ == "__main__": main()
