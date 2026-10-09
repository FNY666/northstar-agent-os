"""al_47: simple utility module (stdlib only)."""

def half(x):
    return x / 2

def _run_tests():
    assert half(10) == 5.0, 'al_47'
    assert half(1) == 0.5, 'al_47'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_47: all tests passed")
