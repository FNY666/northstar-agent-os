"""al_18: simple utility module (stdlib only)."""

def abs_val(x):
    return x if x >= 0 else -x

def _run_tests():
    assert abs_val(-5) == 5, 'al_18'
    assert abs_val(5) == 5, 'al_18'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_18: all tests passed")
