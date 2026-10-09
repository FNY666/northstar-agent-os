"""snake_case to camelCase (AB-32), Simulated."""
from __future__ import annotations
import ast

VERSION = "snake2camel.v1"
def snake_to_camel(s: str) -> str:
    w = s.split("_")
    return w[0] + "".join(x.capitalize() for x in w[1:])
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "re", "math", "base64", "hashlib", "hmac", "urllib", "collections", "itertools", "string", "json", "bisect"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert snake_to_camel("foo_bar") == "fooBar"
    assert snake_to_camel("x") == "x"
    assert stdlib_only()
    print("snake2camel OK")
if __name__ == "__main__": main()
