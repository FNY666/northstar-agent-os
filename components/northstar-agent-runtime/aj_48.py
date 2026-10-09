"""AJ-48: Edit distance."""
from __future__ import annotations
VERSION = "aj_48.v1"


def levenshtein(a, b):
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j]+1, cur[-1]+1, prev[j-1]+(ca != cb)))
        prev = cur
    return prev[-1]

def main() -> None:
    assert levenshtein('kitten','sitting') == 3
    assert levenshtein('','abc') == 3
    print(f"aj_48 OK")
if __name__ == "__main__": main()
