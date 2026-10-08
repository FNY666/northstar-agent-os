"""Toxicity detection mock (D-OUT-009), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "toxicity-mock.v1"
TOXIC_PATTERNS = [r"\bhate\b", r"\bkill\b", r"\bstupid\b"]
def score(text: str) -> float:
    """Mock toxicity score 0.0-1.0."""
    t = text.lower()
    hits = sum(1 for p in TOXIC_PATTERNS if re.search(p, t))
    return min(1.0, hits * 0.4)
def is_toxic(text: str, threshold: float = 0.5) -> bool:
    return score(text) >= threshold
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert is_toxic("I hate you, kill them")
    assert not is_toxic("hello world")
    assert stdlib_only()
    print("toxicity-mock OK")
if __name__ == "__main__": main()
