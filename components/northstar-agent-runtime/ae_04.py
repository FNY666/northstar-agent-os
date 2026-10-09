"""AE-module: square -- x squared."""
from __future__ import annotations
VERSION = "ae_04.v1"
def square(x: float) -> float:
    return x * x

def main() -> None:
    assert square(3) == 9
    assert square(-2.5) == 6.25
    assert square(0) == 0
    print("ae_04 square OK")
if __name__ == "__main__": main()
