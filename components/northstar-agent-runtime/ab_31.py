"""camelCase to snake_case (AB-31), Simulated."""
from __future__ import annotations
import ast
import re
VERSION = "camel2snake.v1"
def camel_to_snake(s: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", s).lower()
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
    assert camel_to_snake("fooBar") == "foo_bar"
    assert camel_to_snake("x") == "x"
    assert stdlib_only()
    print("camel2snake OK")
if __name__ == "__main__": main()
