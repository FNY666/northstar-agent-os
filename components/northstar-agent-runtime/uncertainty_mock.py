"""Uncertainty quantification mock (D-OUT-016), Simulated."""
from __future__ import annotations
import ast
VERSION = "uncertainty-mock.v1"
def quantify(text: str) -> float:
    """Mock uncertainty 0.0-1.0. Higher = more uncertain."""
    hedges = ["maybe", "possibly", "might", "could be", "uncertain"]
    t = text.lower()
    hits = sum(1 for h in hedges if h in t)
    return min(1.0, hits * 0.25)
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
    assert quantify("maybe possibly") > 0.4
    assert quantify("definitely") == 0.0
    assert stdlib_only()
    print("uncertainty-mock OK")
if __name__ == "__main__": main()
