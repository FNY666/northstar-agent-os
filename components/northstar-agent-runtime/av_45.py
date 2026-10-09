"""Integer square root (floor)."""
import math
def isqrt(n):
    if n < 0:
        raise ValueError("negative")
    return math.isqrt(n)
if __name__ == "__main__":
    assert isqrt(16) == 4
    assert isqrt(20) == 4
    assert isqrt(0) == 0
    print("ok")
