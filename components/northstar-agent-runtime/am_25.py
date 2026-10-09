"""am_25: repeat_str utility (stdlib only)."""

def repeat_str(s, n):
    return s * n

def _run_tests():
    assert repeat_str('ab', 3) == 'ababab', 'am_25'
    assert repeat_str('x', 0) == '', 'am_25'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_25: all tests passed")
