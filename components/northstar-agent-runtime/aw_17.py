"""Least common multiple of two ints."""
def lcm_of(a, b):
    if a == 0 or b == 0:
        return 0
    x, y = a, b
    while y:
        x, y = y, x % y
    return abs(a * b) // abs(x)
if __name__ == "__main__":
    assert lcm_of(4, 6) == 12
    assert lcm_of(7, 5) == 35
    assert lcm_of(0, 5) == 0
    print("ok")
