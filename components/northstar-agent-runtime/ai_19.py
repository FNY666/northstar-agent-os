"""Levenshtein Util (AI-U-019), Simulated."""
from __future__ import annotations
VERSION = "ai_19.v1"

def levenshtein(a, b):
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        ndp, dp = [i], dp
        for j, cb in enumerate(b, 1):
            ndp.append(min(dp[j] + 1, ndp[j - 1] + 1, dp[j - 1] + (ca != cb)))
        dp = ndp
    return dp[-1]

def main() -> None:
    assert levenshtein('kitten', 'sitting') == 3
    assert levenshtein('', 'abc') == 3
    print(f"ai_19 OK")
if __name__ == "__main__": main()
