"""Y-module: triangular -- Nth triangular number."""
from __future__ import annotations
VERSION = "y_32.v1"
def triangular(n: int) -> int:
    return n * (n + 1) // 2

def main() -> None:
    assert triangular(4) == 10
    assert triangular(0) == 0
    print("y_32 triangular OK")
if __name__ == "__main__": main()
