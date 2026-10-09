"""Least common multiple of two ints."""
import math
def lcm(a, b):
    if a == 0 or b == 0:
        return 0
    return abs(a * b) // math.gcd(a, b)
if __name__ == "__main__":
    assert lcm(4, 6) == 12
    assert lcm(7, 5) == 35
    assert lcm(0, 9) == 0
    print("ok")
