"""AF-module: factorial -- Iterative factorial; raises for negatives."""
from __future__ import annotations
VERSION = "af_18"
def factorial(n: int) -> int:
    if n < 0:
        raise ValueError('n must be >= 0')
    out = 1
    for i in range(2, n + 1):
        out *= i
    return out

def main() -> None:
    assert factorial(0) == 1
    assert factorial(5) == 120
    try:
        factorial(-1); raise SystemExit('nope')
    except ValueError:
        pass
    print("af_18 factorial OK")
if __name__ == "__main__": main()
