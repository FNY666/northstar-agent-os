"""ReLU Util (AI-U-003), Simulated."""
from __future__ import annotations
VERSION = "ai_03.v1"

def relu(x):
    return x if x > 0 else 0

def main() -> None:
    assert relu(3) == 3
    assert relu(-2) == 0 and relu(0) == 0
    print(f"ai_03 OK")
if __name__ == "__main__": main()
