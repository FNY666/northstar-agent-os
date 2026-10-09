"""ax_09: gcd utility (stdlib only)."""
def gcd(a, b):
    while b: a, b = b, a % b
    return abs(a)


def run_tests():
    assert (gcd(12, 18)) == 6, 'gcd(12, 18)'
    assert (gcd(7, 5)) == 1, 'gcd(7, 5)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_09: ok")
