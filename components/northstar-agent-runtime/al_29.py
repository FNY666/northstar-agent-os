"""al_29: simple utility module (stdlib only)."""

def to_upper(s):
    return s.upper()

def _run_tests():
    assert to_upper('abc') == 'ABC', 'al_29'
    assert to_upper('xY') == 'XY', 'al_29'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_29: all tests passed")
