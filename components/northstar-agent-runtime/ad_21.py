"""AD-module: first_char -- Return the first character of a string."""
from __future__ import annotations
VERSION = "ad_21.v1"
def first_char(s: str) -> str:
    return s[0] if s else ""

def main() -> None:
    assert first_char("abc") == "a"
    assert first_char("") == ""
    assert first_char("z") == "z"
    print("ad_21 first_char OK")
if __name__ == "__main__": main()
