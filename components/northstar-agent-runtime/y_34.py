"""Y-module: interleave -- Interleave two lists."""
from __future__ import annotations
VERSION = "y_34.v1"
def interleave(a: list, b: list) -> list:
    out = []
    for x, y in zip(a, b): out += [x, y]
    return out + a[len(b):] + b[len(a):]

def main() -> None:
    assert interleave([1, 2], [3, 4]) == [1, 3, 2, 4]
    assert interleave([1], []) == [1]
    print("y_34 interleave OK")
if __name__ == "__main__": main()
