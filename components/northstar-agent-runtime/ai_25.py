"""One-Hot Util (AI-U-025), Simulated."""
from __future__ import annotations
VERSION = "ai_25.v1"

def one_hot(idx, size):
    v = [0] * size
    v[idx] = 1
    return v

def main() -> None:
    assert one_hot(2, 4) == [0, 0, 1, 0]
    assert one_hot(0, 1) == [1]
    print(f"ai_25 OK")
if __name__ == "__main__": main()
