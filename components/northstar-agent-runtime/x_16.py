"""X-module: human_secs -- Seconds to human duration."""
from __future__ import annotations
VERSION = "x_16.v1"
def human_secs(s: int) -> str:
    if s < 0: raise ValueError("s must be >= 0")
    h, s = divmod(s, 3600); m, s = divmod(s, 60)
    return f"{h}h {m}m {s}s"

def main() -> None:
    assert human_secs(0) == "0h 0m 0s"
    assert human_secs(3661) == "1h 1m 1s"
    print("x_16 human_secs OK")
if __name__ == "__main__": main()
