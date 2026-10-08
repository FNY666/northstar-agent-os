"""X-module: truncate -- Truncate string with ellipsis."""
from __future__ import annotations
VERSION = "x_12.v1"
def truncate(s: str, n: int) -> str:
    if n < 0: raise ValueError("n must be >= 0")
    return s if len(s) <= n else s[:n] + "..."

def main() -> None:
    assert truncate("hello", 10) == "hello"
    assert truncate("hello world", 5) == "hello..."
    print("x_12 truncate OK")
if __name__ == "__main__": main()
