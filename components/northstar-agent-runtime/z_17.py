"""z_17: mode."""
from __future__ import annotations
VERSION = "z_17.v1"
def mode(xs):
    from collections import Counter
    return Counter(xs).most_common(1)[0][0]

def main() -> None:
    assert mode([1,2,2,3])==2
    assert mode([5])==5
    print('z_17 mode OK')

if __name__ == "__main__": main()
