"""am_13: decrement utility (stdlib only)."""

def decrement(x):
    return x - 1

def _run_tests():
    assert decrement(1) == 0, 'am_13'
    assert decrement(-1) == -2, 'am_13'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_13: all tests passed")
