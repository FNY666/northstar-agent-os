"""am_50: to_str utility (stdlib only)."""

def to_str(x):
    return str(x)

def _run_tests():
    assert to_str(42) == '42', 'am_50'
    assert to_str(None) == 'None', 'am_50'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_50: all tests passed")
