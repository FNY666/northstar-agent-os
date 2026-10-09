"""AF-module: fib_list -- First n Fibonacci numbers starting at 0."""
from __future__ import annotations
VERSION = "af_19"
def fib_list(n: int) -> list:
    out: list = []
    a, b = 0, 1
    for _ in range(max(0, n)):
        out.append(a)
        a, b = b, a + b
    return out

def main() -> None:
    assert fib_list(7) == [0, 1, 1, 2, 3, 5, 8]
    assert fib_list(0) == []
    assert fib_list(1) == [0]
    print("af_19 fib_list OK")
if __name__ == "__main__": main()
