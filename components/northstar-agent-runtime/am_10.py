"""am_10: half utility (stdlib only)."""

def half(x):
    return x / 2

def _run_tests():
    assert half(10) == 5.0, 'am_10'
    assert half(7) == 3.5, 'am_10'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_10: all tests passed")
