"""am_05: is_even utility (stdlib only)."""

def is_even(x):
    return x % 2 == 0

def _run_tests():
    assert is_even(4) is True, 'am_05'
    assert is_even(5) is False, 'am_05'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_05: all tests passed")
