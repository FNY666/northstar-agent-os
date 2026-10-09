"""AE-module: clamp01 -- Clamp a float into [0.0, 1.0]."""
from __future__ import annotations
VERSION = "ae_49.v1"
def clamp01(v: float) -> float:
    return max(0.0, min(1.0, v))

def main() -> None:
    assert clamp01(0.5) == 0.5
    assert clamp01(-1) == 0.0
    assert clamp01(2) == 1.0
    print("ae_49 clamp01 OK")
if __name__ == "__main__": main()
