"""AE-module: cube -- x cubed."""
from __future__ import annotations
VERSION = "ae_05.v1"
def cube(x: float) -> float:
    return x ** 3

def main() -> None:
    assert cube(2) == 8
    assert cube(-3) == -27
    assert cube(0.5) == 0.125
    print("ae_05 cube OK")
if __name__ == "__main__": main()
