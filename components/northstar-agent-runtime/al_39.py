"""al_39: simple utility module (stdlib only)."""

def clamp_zero_one(x):
    return max(0, min(1, x))

def _run_tests():
    assert clamp_zero_one(0.5) == 0.5, 'al_39'
    assert clamp_zero_one(5) == 1, 'al_39'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_39: all tests passed")
