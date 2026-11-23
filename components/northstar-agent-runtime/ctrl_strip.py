"""Control char stripping (D-IN-006), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "ctrl-strip.v1"
def clean(t: str) -> str:
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", t)
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
    assert clean("a\x00b") == "ab"
    assert clean("a\nb") == "a\nb"
    assert stdlib_only()
    print("ctrl-strip OK")
if __name__ == "__main__": main()
