"""ao_04: lcm utility (stdlib only)."""

from math import gcd
def lcm(a, b):
    return a * b // gcd(a, b)


def _self_test():
    assert lcm(4, 6) == 12, 'lcm(4, 6) == 12'
    assert lcm(7, 5) == 35, 'lcm(7, 5) == 35'


if __name__ == "__main__":
    _self_test()
    print("ok")
