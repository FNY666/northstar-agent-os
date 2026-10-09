"""am_19: is_positive utility (stdlib only)."""

def is_positive(x):
    return x > 0

def _run_tests():
    assert is_positive(1) is True, 'am_19'
    assert is_positive(0) is False, 'am_19'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_19: all tests passed")
