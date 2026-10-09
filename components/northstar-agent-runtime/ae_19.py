"""AE-module: pad_right -- s left-justified to width with fill."""
from __future__ import annotations
VERSION = "ae_19.v1"
def pad_right(s: str, width: int, fill: str = ' ') -> str:
    return s.ljust(width, fill)

def main() -> None:
    assert pad_right("5", 3, "0") == "500"
    assert pad_right("ab", 2) == "ab"
    assert pad_right("", 2) == "  "
    print("ae_19 pad_right OK")
if __name__ == "__main__": main()
