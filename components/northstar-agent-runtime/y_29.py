"""Y-module: pct_change -- Percent change from old to new."""
from __future__ import annotations
VERSION = "y_29.v1"
def pct_change(old: float, new: float) -> float:
    return (new - old) / old * 100 if old else 0.0

def main() -> None:
    assert pct_change(100, 120) == 20.0
    assert pct_change(0, 5) == 0.0
    print("y_29 pct_change OK")
if __name__ == "__main__": main()
