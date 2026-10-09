"""am_01: add_three utility (stdlib only)."""

def add_three(x):
    return x + 3

def _run_tests():
    assert add_three(0) == 3, 'am_01'
    assert add_three(-3) == 0, 'am_01'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_01: all tests passed")
