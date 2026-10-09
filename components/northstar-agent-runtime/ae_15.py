"""AE-module: snake_to_camel -- snake_case to camelCase."""
from __future__ import annotations
VERSION = "ae_15.v1"
def snake_to_camel(s: str) -> str:
    parts = s.split('_')
    return parts[0] + ''.join(p[:1].upper() + p[1:] for p in parts[1:])

def main() -> None:
    assert snake_to_camel("hello_world") == "helloWorld"
    assert snake_to_camel("x") == "x"
    assert snake_to_camel("a_b_c") == "aBC"
    print("ae_15 snake_to_camel OK")
if __name__ == "__main__": main()
