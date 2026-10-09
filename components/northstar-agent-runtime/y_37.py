"""Y-module: truncate -- Truncate with ellipsis."""
from __future__ import annotations
VERSION = "y_37.v1"
def truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:max(0, n-3)] + "..."

def main() -> None:
    assert truncate("hello", 10) == "hello"
    assert truncate("hello world", 8) == "hello..."
    print("y_37 truncate OK")
if __name__ == "__main__": main()
