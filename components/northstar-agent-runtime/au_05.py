"""au_05: GCD and LCM of two ints."""
import math
def gcd_lcm(a, b):
    """Return (gcd, lcm) of a and b."""
    g = math.gcd(a, b)
    return (g, abs(a*b)//g if g else 0)

def _run_tests():
    assert gcd_lcm(12, 18) == (6, 36)
    assert gcd_lcm(7, 5) == (1, 35)

if __name__ == "__main__":
    _run_tests()
    print("au_05 OK")
