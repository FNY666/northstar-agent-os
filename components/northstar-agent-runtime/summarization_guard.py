"""Summarization guard (D-OUT-020), Simulated."""
from __future__ import annotations
import ast
VERSION = "summarization-guard.v1"
def check_summary(original: str, summary: str, max_ratio: float = 0.3) -> bool:
    return len(summary) <= len(original) * max_ratio + 100
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
    assert check_summary("x"*1000, "short")
    assert not check_summary("short", "x"*1000)
    assert stdlib_only()
    print("summarization-guard OK")
if __name__ == "__main__": main()
