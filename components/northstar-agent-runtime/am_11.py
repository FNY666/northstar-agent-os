"""am_11: triple utility (stdlib only)."""

def triple(x):
    return x * 3

def _run_tests():
    assert triple(4) == 12, 'am_11'
    assert triple(0) == 0, 'am_11'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_11: all tests passed")
