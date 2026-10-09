"""am_49: to_float utility (stdlib only)."""

def to_float(x):
    return float(x)

def _run_tests():
    assert to_float('1.5') == 1.5, 'am_49'
    assert to_float(2) == 2.0, 'am_49'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_49: all tests passed")
