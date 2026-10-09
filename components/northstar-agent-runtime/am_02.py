"""am_02: subtract_one utility (stdlib only)."""

def subtract_one(x):
    return x - 1

def _run_tests():
    assert subtract_one(5) == 4, 'am_02'
    assert subtract_one(0) == -1, 'am_02'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_02: all tests passed")
