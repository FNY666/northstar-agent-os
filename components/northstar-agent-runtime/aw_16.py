"""Greatest common divisor of two ints."""
def gcd_of(a, b):
    while b:
        a, b = b, a % b
    return abs(a)
if __name__ == "__main__":
    assert gcd_of(12, 8) == 4
    assert gcd_of(7, 5) == 1
    assert gcd_of(-6, 9) == 3
    print("ok")
