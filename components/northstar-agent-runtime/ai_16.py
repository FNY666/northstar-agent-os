"""N-Grams Util (AI-U-016), Simulated."""
from __future__ import annotations
VERSION = "ai_16.v1"

def ngrams(tokens, n):
    return [tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1)]

def main() -> None:
    assert ngrams(['a', 'b', 'c'], 2) == [('a', 'b'), ('b', 'c')]
    assert ngrams(['a'], 2) == []
    print(f"ai_16 OK")
if __name__ == "__main__": main()
