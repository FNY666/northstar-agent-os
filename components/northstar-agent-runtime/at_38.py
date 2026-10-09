"""at_38: percent -- Percent p of total."""
from __future__ import annotations
VERSION = "at_38.v1"
def percent(p, total):
    return total * p / 100

def main() -> None:
    assert percent(50, 200) == 100.0
    assert percent(0, 5) == 0
    print("at_38 percent OK")
if __name__ == "__main__": main()
