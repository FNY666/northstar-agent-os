"""al_30: simple utility module (stdlib only)."""

def to_lower(s):
    return s.lower()

def _run_tests():
    assert to_lower('ABC') == 'abc', 'al_30'
    assert to_lower('xY') == 'xy', 'al_30'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_30: all tests passed")
