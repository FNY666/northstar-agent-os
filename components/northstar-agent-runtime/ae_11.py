"""AE-module: reverse_string -- s reversed."""
from __future__ import annotations
VERSION = "ae_11.v1"
def reverse_string(s: str) -> str:
    return s[::-1]

def main() -> None:
    assert reverse_string("abc") == "cba"
    assert reverse_string("") == ""
    assert reverse_string("a") == "a"
    print("ae_11 reverse_string OK")
if __name__ == "__main__": main()
