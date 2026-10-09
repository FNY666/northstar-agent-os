"""AJ-39: Lerp."""
from __future__ import annotations
VERSION = "aj_39.v1"


def lerp(a, b, t):
    return a + (b - a) * t

def main() -> None:
    assert lerp(0, 10, 0.5) == 5.0
    assert lerp(2, 8, 0) == 2
    print(f"aj_39 OK")
if __name__ == "__main__": main()
