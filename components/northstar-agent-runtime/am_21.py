"""am_21: reverse_str utility (stdlib only)."""

def reverse_str(s):
    return s[::-1]

def _run_tests():
    assert reverse_str('abc') == 'cba', 'am_21'
    assert reverse_str('') == '', 'am_21'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_21: all tests passed")
