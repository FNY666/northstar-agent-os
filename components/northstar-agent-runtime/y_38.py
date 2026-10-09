"""Y-module: pad_left -- Left-pad string to width."""
from __future__ import annotations
VERSION = "y_38.v1"
def pad_left(s: str, width: int, fill: str = " ") -> str:
    return s.rjust(width, fill)

def main() -> None:
    assert pad_left("7", 3, "0") == "007"
    assert pad_left("ab", 2) == "ab"
    print("y_38 pad_left OK")
if __name__ == "__main__": main()
