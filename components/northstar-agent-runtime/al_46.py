"""al_46: simple utility module (stdlib only)."""

def constant_seven():
    return 7

def _run_tests():
    assert constant_seven() == 7, 'al_46'
    assert constant_seven() + 1 == 8, 'al_46'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_46: all tests passed")
