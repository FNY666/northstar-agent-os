"""Percent Change."""
from __future__ import annotations
import ast

VERSION = "ah_08.v1"
def percent_change(old: float, new: float) -> float:
    return (new - old) / old * 100.0 if old else 0.0
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "itertools", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert percent_change(100, 120) == 20.0
    assert percent_change(0, 5) == 0.0
    assert stdlib_only()
    print("ah_08 OK")
if __name__ == "__main__": main()
