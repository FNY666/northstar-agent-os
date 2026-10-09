"""AD-module: upper_first -- Capitalize the first character of a string."""
from __future__ import annotations
VERSION = "ad_18.v1"
def upper_first(s: str) -> str:
    return s[:1].upper() + s[1:] if s else s

def main() -> None:
    assert upper_first("hello") == "Hello"
    assert upper_first("") == ""
    assert upper_first("a") == "A"
    print("ad_18 upper_first OK")
if __name__ == "__main__": main()
