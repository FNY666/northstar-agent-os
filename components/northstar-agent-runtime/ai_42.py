"""LR Schedule Util (AI-U-042), Simulated."""
from __future__ import annotations
VERSION = "ai_42.v1"

def lr_decay(step, lr0, decay=0.99):
    return lr0 * (decay ** step)

def main() -> None:
    assert abs(lr_decay(0, 0.1) - 0.1) < 1e-12
    assert abs(lr_decay(2, 1.0) - 0.9801) < 1e-12
    print(f"ai_42 OK")
if __name__ == "__main__": main()
