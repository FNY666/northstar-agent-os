"""XSS detection in output (D-OUT-024), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "xss-detect.v1"
PATTERNS = [r"<script", r"javascript:", r"on\w+\s*="]
def detect(text: str) -> list:
    return [p for p in PATTERNS if re.search(p, text, re.IGNORECASE)]
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
    assert len(detect("<script>alert(1)</script>")) > 0
    assert len(detect("hello")) == 0
    assert stdlib_only()
    print("xss-detect OK")
if __name__ == "__main__": main()
