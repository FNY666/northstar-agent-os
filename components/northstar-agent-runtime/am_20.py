"""am_20: sign utility (stdlib only)."""

def sign(x):
    return (x > 0) - (x < 0)

def _run_tests():
    assert sign(5) == 1, 'am_20'
    assert sign(-5) == -1 and sign(0) == 0, 'am_20'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_20: all tests passed")
