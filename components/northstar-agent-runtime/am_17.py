"""am_17: factorial_small utility (stdlib only)."""

def factorial_small(n):
    r = 1
    for i in range(2, n + 1):
        r *= i
    return r

def _run_tests():
    assert factorial_small(5) == 120, 'am_17'
    assert factorial_small(0) == 1, 'am_17'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_17: all tests passed")
