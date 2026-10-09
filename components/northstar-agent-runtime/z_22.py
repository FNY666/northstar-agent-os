"""z_22: truncate."""
from __future__ import annotations
VERSION = "z_22.v1"
def truncate(s,n):
    return s if len(s)<=n else s[:n-1]+'…'

def main() -> None:
    assert truncate('abcdef',4)=='abc…'
    assert truncate('ab',5)=='ab'
    print('z_22 truncate OK')

if __name__ == "__main__": main()
