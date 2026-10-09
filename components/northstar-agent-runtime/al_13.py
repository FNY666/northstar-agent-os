"""al_13: simple utility module (stdlib only)."""

def is_positive(x):
    return x > 0

def _run_tests():
    assert is_positive(5) == True, 'al_13'
    assert is_positive(-1) == False, 'al_13'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_13: all tests passed")
