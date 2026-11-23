"""Refusal detection (D-OUT-017), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "refusal-detect.v1"
PATTERNS = [r"I can't", r"I'm unable", r"I cannot", r"not allowed"]
def is_refusal(text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in PATTERNS)
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
    assert is_refusal("I can't help")
    assert not is_refusal("hello")
    assert stdlib_only()
    print("refusal-detect OK")
if __name__ == "__main__": main()
