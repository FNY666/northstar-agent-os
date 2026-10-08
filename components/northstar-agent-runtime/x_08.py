"""X-module: dedupe -- Remove duplicates preserving order."""
from __future__ import annotations
VERSION = "x_08.v1"
def dedupe(xs: list) -> list:
    seen, out = set(), []
    for x in xs:
        if x not in seen: seen.add(x); out.append(x)
    return out

def main() -> None:
    assert dedupe([1, 2, 1, 3, 2]) == [1, 2, 3]
    assert dedupe([]) == []
    print("x_08 dedupe OK")
if __name__ == "__main__": main()
