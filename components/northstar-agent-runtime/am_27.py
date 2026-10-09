"""am_27: starts_with_a utility (stdlib only)."""

def starts_with_a(s):
    return s.startswith('a')

def _run_tests():
    assert starts_with_a('abc') is True, 'am_27'
    assert starts_with_a('xyz') is False, 'am_27'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_27: all tests passed")
