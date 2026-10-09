"""Greatest common divisor of a list of ints."""
import math
def gcd_list(nums):
    g = 0
    for n in nums:
        g = math.gcd(g, n)
    return g
if __name__ == "__main__":
    assert gcd_list([12, 18, 24]) == 6
    assert gcd_list([7]) == 7
    assert gcd_list([0, 5]) == 5
    print("ok")
