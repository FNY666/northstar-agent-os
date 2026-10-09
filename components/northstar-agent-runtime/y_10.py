"""Y-module: factorial -- Iterative factorial."""
from __future__ import annotations
VERSION = "y_10.v1"
def factorial(n: int) -> int:
    r = 1
    for i in range(2, n + 1): r *= i
    return r

def main() -> None:
    assert factorial(5) == 120
    assert factorial(0) == 1
    print("y_10 factorial OK")
if __name__ == "__main__": main()
