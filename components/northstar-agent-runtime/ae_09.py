"""AE-module: fibonacci -- n-th Fibonacci number (0-indexed)."""
from __future__ import annotations
VERSION = "ae_09.v1"
def fibonacci(n: int) -> int:
    if n < 0:
        raise ValueError('negative')
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

def main() -> None:
    assert fibonacci(0) == 0
    assert fibonacci(1) == 1
    assert fibonacci(10) == 55
    print("ae_09 fibonacci OK")
if __name__ == "__main__": main()
