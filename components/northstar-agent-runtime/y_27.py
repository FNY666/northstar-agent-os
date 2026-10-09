"""Y-module: sign -- Sign of a number (-1/0/1)."""
from __future__ import annotations
VERSION = "y_27.v1"
def sign(v: float) -> int:
    return (v > 0) - (v < 0)

def main() -> None:
    assert sign(-3.5) == -1
    assert sign(0) == 0
    print("y_27 sign OK")
if __name__ == "__main__": main()
