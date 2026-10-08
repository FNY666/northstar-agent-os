"""Code output scanning (D-OUT-022), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "code-scan.v1"
DANGEROUS = [r"\bos\.system\b", r"\beval\b", r"\bexec\b", r"__import__"]
def scan(code: str) -> list:
    found = []
    for pat in DANGEROUS:
        if re.search(pat, code):
            found.append(pat)
    return found
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
    assert len(scan("os.system('rm')")) > 0
    assert len(scan("print('hi')")) == 0
    assert stdlib_only()
    print("code-scan OK")
if __name__ == "__main__": main()
