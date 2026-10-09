"""Backoff Delay Util (AI-U-041), Simulated."""
from __future__ import annotations
VERSION = "ai_41.v1"

def backoff(attempt, base=1.0, cap=60.0):
    return min(base * (2 ** attempt), cap)

def main() -> None:
    assert backoff(0) == 1.0
    assert backoff(10) == 60.0 and backoff(2) == 4.0
    print(f"ai_41 OK")
if __name__ == "__main__": main()
