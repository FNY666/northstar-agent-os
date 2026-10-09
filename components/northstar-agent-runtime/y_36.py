"""Y-module: in_range -- Inclusive range check."""
from __future__ import annotations
VERSION = "y_36.v1"
def in_range(v: float, lo: float, hi: float) -> bool:
    return lo <= v <= hi

def main() -> None:
    assert in_range(5, 0, 10) is True
    assert in_range(11, 0, 10) is False
    print("y_36 in_range OK")
if __name__ == "__main__": main()
