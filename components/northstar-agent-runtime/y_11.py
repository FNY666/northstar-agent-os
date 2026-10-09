"""Y-module: fib_n -- Nth Fibonacci number (0-indexed)."""
from __future__ import annotations
VERSION = "y_11.v1"
def fib_n(n: int) -> int:
    a, b = 0, 1
    for _ in range(n): a, b = b, a + b
    return a

def main() -> None:
    assert fib_n(10) == 55
    assert fib_n(0) == 0
    print("y_11 fib_n OK")
if __name__ == "__main__": main()
