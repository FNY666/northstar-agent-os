"""am_08: abs_val utility (stdlib only)."""

def abs_val(x):
    return x if x >= 0 else -x

def _run_tests():
    assert abs_val(-7) == 7, 'am_08'
    assert abs_val(7) == 7, 'am_08'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_08: all tests passed")
