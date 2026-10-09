"""lcm utility."""

def lcm(a, b):
    from math import gcd
    return abs(a*b)//gcd(a, b) if a and b else 0


def _self_test():
    assert lcm(4, 6) == 12
    assert lcm(0, 5) == 0


if __name__ == "__main__":
    _self_test()
    print("ap_42: OK")
