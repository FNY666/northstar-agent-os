"""ax_10: lcm utility (stdlib only)."""
def lcm(a, b):
    from math import gcd as _g
    return abs(a * b) // _g(a, b) if a and b else 0


def run_tests():
    assert (lcm(4, 6)) == 12, 'lcm(4, 6)'
    assert (lcm(0, 5)) == 0, 'lcm(0, 5)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_10: ok")
