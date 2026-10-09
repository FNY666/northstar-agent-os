"""al_02: simple utility module (stdlib only)."""

def triple(x):
    return x * 3

def _run_tests():
    assert triple(4) == 12, 'al_02'
    assert triple(0) == 0, 'al_02'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_02: all tests passed")
