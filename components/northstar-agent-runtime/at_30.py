"""at_30: head -- First n items."""
from __future__ import annotations
VERSION = "at_30.v1"
def head(xs, n=1):
    return xs[:n]

def main() -> None:
    assert head([1, 2, 3]) == [1]
    assert head([1, 2], 2) == [1, 2]
    print("at_30 head OK")
if __name__ == "__main__": main()
