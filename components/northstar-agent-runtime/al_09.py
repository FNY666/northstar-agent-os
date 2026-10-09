"""al_09: simple utility module (stdlib only)."""

def decrement(x):
    return x - 1

def _run_tests():
    assert decrement(5) == 4, 'al_09'
    assert decrement(0) == -1, 'al_09'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_09: all tests passed")
