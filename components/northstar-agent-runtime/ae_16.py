"""AE-module: camel_to_snake -- camelCase to snake_case."""
from __future__ import annotations
VERSION = "ae_16.v1"
def camel_to_snake(s: str) -> str:
    out = ''.join('_' + c.lower() if c.isupper() else c for c in s)
    return out.lstrip('_')

def main() -> None:
    assert camel_to_snake("helloWorld") == "hello_world"
    assert camel_to_snake("x") == "x"
    assert camel_to_snake("HelloWorld") == "hello_world"
    print("ae_16 camel_to_snake OK")
if __name__ == "__main__": main()
