"""Top-K Util (AI-U-008), Simulated."""
from __future__ import annotations
VERSION = "ai_08.v1"

def top_k(xs, k):
    return sorted(range(len(xs)), key=lambda i: xs[i], reverse=True)[:k]

def main() -> None:
    assert top_k([1, 9, 3, 7], 2) == [1, 3]
    assert top_k([5], 3) == [0]
    print(f"ai_08 OK")
if __name__ == "__main__": main()
