"""am_12: increment utility (stdlib only)."""

def increment(x):
    return x + 1

def _run_tests():
    assert increment(9) == 10, 'am_12'
    assert increment(-1) == 0, 'am_12'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_12: all tests passed")
