"""Citation verification (D-OUT-013), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "citation-verify.v1"
def extract_citations(text: str) -> list:
    return re.findall(r"\[(\d+)\]", text)
def verify(text: str, sources: list) -> tuple[bool, str]:
    cites = extract_citations(text)
    if not cites: return True, "no citations to verify"
    for c in cites:
        if int(c) > len(sources):
            return False, f"citation [{c}] has no source"
    return True, "ok"
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
    assert verify("See [1]", ["s1"])[0]
    assert not verify("See [2]", ["s1"])[0]
    assert stdlib_only()
    print("citation-verify OK")
if __name__ == "__main__": main()
