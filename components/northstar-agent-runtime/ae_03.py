"""AE-module: sign -- -1, 0, or 1 for negative, zero, positive x."""
from __future__ import annotations
VERSION = "ae_03.v1"
def sign(x: float) -> int:
    if x > 0:
        return 1
    if x < 0:
        return -1
    return 0

def main() -> None:
    assert sign(3.5) == 1
    assert sign(-2) == -1
    assert sign(0) == 0
    print("ae_03 sign OK")
if __name__ == "__main__": main()
