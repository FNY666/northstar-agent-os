"""an_42: least common multiple. Stdlib only."""

def lcm(a, b):
    from math import gcd as g
    return abs(a * b) // g(a, b)

if __name__ == "__main__":
    assert lcm(4, 6) == 12
    assert lcm(5, 5) == 5
    print("ok")
