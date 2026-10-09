"""am_07: negate utility (stdlib only)."""

def negate(x):
    return -x

def _run_tests():
    assert negate(5) == -5, 'am_07'
    assert negate(-5) == 5, 'am_07'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_07: all tests passed")
