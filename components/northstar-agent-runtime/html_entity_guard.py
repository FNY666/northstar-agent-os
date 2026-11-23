"""HTML entity decoding guard (D-IN-007), Simulated."""
from __future__ import annotations
import ast, html, re
VERSION = "html-entity-guard.v1"
def has_double_encoding(t: str) -> bool:
    decoded = html.unescape(t)
    return bool(re.search(r"&[a-z]+;", decoded, re.IGNORECASE))
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "html", "pathlib", "re", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert has_double_encoding("&amp;lt;")
    assert not has_double_encoding("hello")
    assert stdlib_only()
    print("html-entity-guard OK")
if __name__ == "__main__": main()
