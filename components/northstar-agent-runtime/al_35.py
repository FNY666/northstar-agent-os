"""al_35: simple utility module (stdlib only)."""

def repeat_string(s, n):
    return s * n

def _run_tests():
    assert repeat_string('ab', 3) == 'ababab', 'al_35'
    assert repeat_string('x', 0) == '', 'al_35'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_35: all tests passed")
