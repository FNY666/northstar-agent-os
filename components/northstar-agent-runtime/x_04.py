"""X-module: factorial -- Factorial of n >= 0."""
from __future__ import annotations
VERSION = "x_04.v1"
def factorial(n: int) -> int:
    if n < 0: raise ValueError("n must be >= 0")
    r = 1
    for i in range(2, n + 1): r *= i
    return r

def main() -> None:
    assert factorial(0) == 1
    assert factorial(5) == 120
    try: factorial(-1); assert False
    except ValueError: pass
    print("x_04 factorial OK")
if __name__ == "__main__": main()
