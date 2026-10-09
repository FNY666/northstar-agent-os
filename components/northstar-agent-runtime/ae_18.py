"""AE-module: pad_left -- s right-justified to width with fill."""
from __future__ import annotations
VERSION = "ae_18.v1"
def pad_left(s: str, width: int, fill: str = ' ') -> str:
    return s.rjust(width, fill)

def main() -> None:
    assert pad_left("5", 3, "0") == "005"
    assert pad_left("ab", 2) == "ab"
    assert pad_left("", 2) == "  "
    print("ae_18 pad_left OK")
if __name__ == "__main__": main()
