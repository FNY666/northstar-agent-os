"""AJ-49: Jaccard."""
from __future__ import annotations
VERSION = "aj_49.v1"


def jaccard(a, b):
    sa, sb = set(a), set(b)
    return len(sa & sb) / len(sa | sb) if sa | sb else 1.0

def main() -> None:
    assert jaccard([1,2],[2,3]) == 1/3
    assert jaccard([],[]) == 1.0
    print(f"aj_49 OK")
if __name__ == "__main__": main()
