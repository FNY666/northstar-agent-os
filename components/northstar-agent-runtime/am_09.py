"""am_09: clamp utility (stdlib only)."""

def clamp(x):
    return max(0, min(10, x))

def _run_tests():
    assert clamp(5) == 5, 'am_09'
    assert clamp(15) == 10 and clamp(-2) == 0, 'am_09'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_09: all tests passed")
