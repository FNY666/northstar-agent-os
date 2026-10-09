"""an_41: greatest common divisor. Stdlib only."""

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

if __name__ == "__main__":
    assert gcd(12, 8) == 4
    assert gcd(7, 5) == 1
    print("ok")
