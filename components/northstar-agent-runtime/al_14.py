"""al_14: simple utility module (stdlib only)."""

def is_negative(x):
    return x < 0

def _run_tests():
    assert is_negative(-5) == True, 'al_14'
    assert is_negative(1) == False, 'al_14'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_14: all tests passed")
