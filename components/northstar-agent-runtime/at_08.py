"""at_08: absv -- Absolute value."""
from __future__ import annotations
VERSION = "at_08.v1"
def absv(x):
    return x if x >= 0 else -x

def main() -> None:
    assert absv(-4) == 4
    assert absv(3) == 3
    print("at_08 absv OK")
if __name__ == "__main__": main()
