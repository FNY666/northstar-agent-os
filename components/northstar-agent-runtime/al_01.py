"""al_01: simple utility module (stdlib only)."""

def double(x):
    return x * 2

def _run_tests():
    assert double(3) == 6, 'al_01'
    assert double(-1) == -2, 'al_01'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_01: all tests passed")
