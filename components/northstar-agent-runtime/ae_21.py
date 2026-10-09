"""AE-module: dedupe -- Remove duplicates, keep first occurrence order."""
from __future__ import annotations
VERSION = "ae_21.v1"
def dedupe(xs: list) -> list:
    seen = []
    for x in xs:
        if x not in seen:
            seen.append(x)
    return seen

def main() -> None:
    assert dedupe([1, 2, 1, 3]) == [1, 2, 3]
    assert dedupe([]) == []
    assert dedupe(['a', 'a']) == ['a']
    print("ae_21 dedupe OK")
if __name__ == "__main__": main()
