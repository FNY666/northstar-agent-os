"""lcm utility."""

def _g(a, b):
    while b:
        a, b = b, a % b
    return a
def lcm(a, b):
    return abs(a * b) // _g(a, b) if a and b else 0


def _selftest():
    assert lcm(4, 6) == 12
    assert lcm(7, 5) == 35


if __name__ == "__main__":
    _selftest()
    print("ok")
