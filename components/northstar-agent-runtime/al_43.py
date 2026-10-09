"""al_43: simple utility module (stdlib only)."""

def sign(x):
    return 1 if x > 0 else (-1 if x < 0 else 0)

def _run_tests():
    assert sign(10) == 1, 'al_43'
    assert sign(-3) == -1, 'al_43'
    assert sign(0) == 0, 'al_43'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_43: all tests passed")
