"""modular exponentiation."""
def pow_mod(b, e, m):
    r, b = 1, b % m
    while e:
        if e & 1:
            r = r * b % m
        b = b * b % m
        e >>= 1
    return r
if __name__ == "__main__":
    assert pow_mod(2, 10, 1000) == 24
    assert pow_mod(5, 0, 7) == 1
    assert pow_mod(3, 3, 5) == 2
    print("ok")
