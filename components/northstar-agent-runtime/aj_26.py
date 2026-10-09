"""AJ-26: Truncate."""
from __future__ import annotations
VERSION = "aj_26.v1"


def truncate(s, n, ell='...'):
    return s if len(s) <= n else s[:n-len(ell)] + ell

def main() -> None:
    assert truncate('hello world', 8) == 'hello...'
    assert truncate('hi', 8) == 'hi'
    print(f"aj_26 OK")
if __name__ == "__main__": main()
