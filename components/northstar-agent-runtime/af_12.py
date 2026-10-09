"""AF-module: backoff_delays -- Exponential backoff delays: base * factor**i for i in range(n)."""
from __future__ import annotations
VERSION = "af_12"
def backoff_delays(n: int, base: float = 1.0, factor: float = 2.0) -> list:
    return [base * (factor ** i) for i in range(max(0, n))]

def main() -> None:
    assert backoff_delays(4) == [1.0, 2.0, 4.0, 8.0]
    assert backoff_delays(0) == []
    assert backoff_delays(2, 0.5, 3.0) == [0.5, 1.5]
    print("af_12 backoff_delays OK")
if __name__ == "__main__": main()
