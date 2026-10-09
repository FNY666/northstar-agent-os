"""AJ-44: Sigmoid."""
from __future__ import annotations
VERSION = "aj_44.v1"


import math
def sigmoid(x):
    return 1.0 / (1.0 + math.exp(-x))

def main() -> None:
    assert abs(sigmoid(0)-0.5) < 1e-9
    assert sigmoid(1000) > 0.999
    print(f"aj_44 OK")
if __name__ == "__main__": main()
