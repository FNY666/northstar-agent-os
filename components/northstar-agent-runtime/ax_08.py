"""ax_08: is_prime utility (stdlib only)."""
def is_prime(n):
    if n < 2: return False
    if n % 2 == 0: return n == 2
    r = int(n ** 0.5)
    return all(n % i for i in range(3, r + 1, 2))


def run_tests():
    assert (is_prime(13)) == True, 'is_prime(13)'
    assert (is_prime(15)) == False, 'is_prime(15)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_08: ok")
