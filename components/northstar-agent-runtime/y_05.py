"""Y-module: reverse_str -- Reverse a string."""
from __future__ import annotations
VERSION = "y_05.v1"
def reverse_str(s: str) -> str:
    return s[::-1]

def main() -> None:
    assert reverse_str("abc") == "cba"
    assert reverse_str("") == ""
    print("y_05 reverse_str OK")
if __name__ == "__main__": main()
