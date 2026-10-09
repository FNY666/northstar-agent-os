"""at_19: strip -- Strip whitespace."""
from __future__ import annotations
VERSION = "at_19.v1"
def strip(s):
    return s.strip()

def main() -> None:
    assert strip('  a ') == 'a'
    assert strip('b') == 'b'
    print("at_19 strip OK")
if __name__ == "__main__": main()
