"""Schema validation (D-IN-028), Simulated."""
from __future__ import annotations
import ast
VERSION = "schema-valid.v1"
def validate(data: dict, schema: dict) -> tuple[bool, str]:
    for k, t in schema.items():
        if k not in data: return False, f"missing {k}"
        if not isinstance(data[k], t): return False, f"{k} wrong type"
    return True, "ok"
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert validate({"a": 1}, {"a": int})[0]
    assert not validate({}, {"a": int})[0]
    assert stdlib_only()
    print("schema-valid OK")
if __name__ == "__main__": main()
