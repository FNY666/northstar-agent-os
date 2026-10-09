"""AD-module: strip_spaces -- Remove leading and trailing whitespace."""
from __future__ import annotations
VERSION = "ad_19.v1"
def strip_spaces(s: str) -> str:
    return s.strip()

def main() -> None:
    assert strip_spaces("  hi  ") == "hi"
    assert strip_spaces("a") == "a"
    assert strip_spaces("   ") == ""
    print("ad_19 strip_spaces OK")
if __name__ == "__main__": main()
