"""al_08: simple utility module (stdlib only)."""

def increment(x):
    return x + 1

def _run_tests():
    assert increment(5) == 6, 'al_08'
    assert increment(-1) == 0, 'al_08'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_08: all tests passed")
