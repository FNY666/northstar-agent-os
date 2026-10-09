"""al_48: simple utility module (stdlib only)."""

def quarter(x):
    return x / 4

def _run_tests():
    assert quarter(8) == 2.0, 'al_48'
    assert quarter(1) == 0.25, 'al_48'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_48: all tests passed")
