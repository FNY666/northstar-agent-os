"""am_06: is_odd utility (stdlib only)."""

def is_odd(x):
    return x % 2 == 1

def _run_tests():
    assert is_odd(3) is True, 'am_06'
    assert is_odd(2) is False, 'am_06'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_06: all tests passed")
