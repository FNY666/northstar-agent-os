"""Unicode sanitization NFKC (D-IN-005), Simulated."""
from __future__ import annotations
import ast, unicodedata
VERSION = "unicode-sanit.v1"
def sanitize(t: str) -> str: return unicodedata.normalize("NFKC", t)
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "unicodedata"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert sanitize("\u0041\u030a") == "\u00c5"
    assert stdlib_only()
    print("unicode-sanit OK")
if __name__ == "__main__": main()
