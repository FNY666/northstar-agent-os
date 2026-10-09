"""at_33: median -- Median of xs."""
from __future__ import annotations
VERSION = "at_33.v1"
def median(xs):
    s = sorted(xs); n = len(s)
    return (s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2) if n else 0

def main() -> None:
    assert median([1, 3, 2]) == 2
    assert median([]) == 0
    print("at_33 median OK")
if __name__ == "__main__": main()
