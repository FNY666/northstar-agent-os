"""AE-module: truncate -- s cut to n chars with '...' suffix when longer."""
from __future__ import annotations
VERSION = "ae_17.v1"
def truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + '...'

def main() -> None:
    assert truncate("hello", 10) == "hello"
    assert truncate("hello world", 5) == "hello..."
    assert truncate("abc", 3) == "abc"
    print("ae_17 truncate OK")
if __name__ == "__main__": main()
