"""al_07: simple utility module (stdlib only)."""

def negate(x):
    return -x

def _run_tests():
    assert negate(5) == -5, 'al_07'
    assert negate(-3) == 3, 'al_07'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_07: all tests passed")
