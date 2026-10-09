"""AD-module: last_char -- Return the last character of a string."""
from __future__ import annotations
VERSION = "ad_22.v1"
def last_char(s: str) -> str:
    return s[-1] if s else ""

def main() -> None:
    assert last_char("abc") == "c"
    assert last_char("") == ""
    assert last_char("z") == "z"
    print("ad_22 last_char OK")
if __name__ == "__main__": main()
