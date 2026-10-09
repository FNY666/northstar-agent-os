"""gcd_all utility."""

from math import gcd
def gcd_all(nums):
    g = 0
    for n in nums:
        g = gcd(g, n)
    return g


def _self_test():
    assert gcd_all([12, 18, 24]) == 6
    assert gcd_all([7]) == 7


if __name__ == "__main__":
    _self_test()
    print("ap_07: OK")
