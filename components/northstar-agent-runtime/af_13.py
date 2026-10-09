"""AF-module: levenshtein -- Edit distance between two strings."""
from __future__ import annotations
VERSION = "af_13"
def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def main() -> None:
    assert levenshtein('kitten', 'sitting') == 3
    assert levenshtein('', '') == 0
    assert levenshtein('abc', 'abc') == 0
    print("af_13 levenshtein OK")
if __name__ == "__main__": main()
