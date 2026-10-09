"""am_23: lower_str utility (stdlib only)."""

def lower_str(s):
    return s.lower()

def _run_tests():
    assert lower_str('ABC') == 'abc', 'am_23'
    assert lower_str('aBc') == 'abc', 'am_23'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_23: all tests passed")
