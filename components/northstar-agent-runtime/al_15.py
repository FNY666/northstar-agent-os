"""al_15: simple utility module (stdlib only)."""

def is_zero(x):
    return x == 0

def _run_tests():
    assert is_zero(0) == True, 'al_15'
    assert is_zero(5) == False, 'al_15'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_15: all tests passed")
