"""al_50: simple utility module (stdlib only)."""

def hundred_times(x):
    return x * 100

def _run_tests():
    assert hundred_times(2) == 200, 'al_50'
    assert hundred_times(-1) == -100, 'al_50'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_50: all tests passed")
