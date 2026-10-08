"""URL decoding guard (D-IN-008), Simulated."""
from __future__ import annotations
import ast, re
from urllib.parse import unquote
VERSION = "url-decode-guard.v1"
def has_encoded_attack(t: str) -> bool:
    decoded = unquote(t)
    return bool(re.search(r"[<>'\";]", decoded))
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "re", "typing", "urllib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert has_encoded_attack("%3Cscript%3E")
    assert not has_encoded_attack("hello")
    assert stdlib_only()
    print("url-decode-guard OK")
if __name__ == "__main__": main()
