"""am_22: upper_str utility (stdlib only)."""

def upper_str(s):
    return s.upper()

def _run_tests():
    assert upper_str('abc') == 'ABC', 'am_22'
    assert upper_str('AbC') == 'ABC', 'am_22'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_22: all tests passed")
