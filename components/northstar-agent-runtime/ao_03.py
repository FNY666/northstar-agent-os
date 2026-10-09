"""ao_03: gcd_pair utility (stdlib only)."""

from math import gcd
def gcd_pair(a, b):
    return gcd(a, b)


def _self_test():
    assert gcd_pair(12, 18) == 6, 'gcd_pair(12, 18) == 6'
    assert gcd_pair(7, 13) == 1, 'gcd_pair(7, 13) == 1'


if __name__ == "__main__":
    _self_test()
    print("ok")
