"""au_25: Power-of-two check."""
def is_power_of_two(n):
    """True if n is a positive power of two."""
    return isinstance(n, int) and n > 0 and (n & (n-1)) == 0

def _run_tests():
    assert is_power_of_two(16)
    assert not is_power_of_two(18)

if __name__ == "__main__":
    _run_tests()
    print("au_25 OK")
