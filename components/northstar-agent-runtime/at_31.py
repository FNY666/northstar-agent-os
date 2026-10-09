"""at_31: tail -- Last n items."""
from __future__ import annotations
VERSION = "at_31.v1"
def tail(xs, n=1):
    return xs[-n:] if n else []

def main() -> None:
    assert tail([1, 2, 3]) == [3]
    assert tail([1, 2], 0) == []
    print("at_31 tail OK")
if __name__ == "__main__": main()
