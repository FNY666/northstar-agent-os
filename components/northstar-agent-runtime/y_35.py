"""Y-module: mode -- Most common element (first wins ties)."""
from __future__ import annotations
VERSION = "y_35.v1"
def mode(xs: list):
    return max(set(xs), key=lambda x: (xs.count(x), -xs.index(x)))

def main() -> None:
    assert mode([1, 2, 2, 3]) == 2
    assert mode([5]) == 5
    print("y_35 mode OK")
if __name__ == "__main__": main()
