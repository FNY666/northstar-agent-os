"""Factuality checking mock (D-OUT-012), Simulated."""
from __future__ import annotations
import ast
VERSION = "factuality-mock.v1"
def check_claim(claim: str) -> float:
    """Mock factuality score 0-1."""
    return 0.8 if len(claim) > 10 else 0.5
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
    assert check_claim("The sky is blue and vast") > 0.7
    assert stdlib_only()
    print("factuality-mock OK")
if __name__ == "__main__": main()
