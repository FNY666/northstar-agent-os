"""Hallucination detection mock (D-OUT-011), Simulated."""
from __future__ import annotations
import ast
VERSION = "hallucination-mock.v1"
def detect(text: str) -> float:
    """Mock hallucination score."""
    return 0.3 if "definitely" in text.lower() else 0.1
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
    assert detect("definitely true") > 0.2
    assert stdlib_only()
    print("hallucination-mock OK")
if __name__ == "__main__": main()
