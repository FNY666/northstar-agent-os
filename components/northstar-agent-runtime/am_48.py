"""am_48: to_int utility (stdlib only)."""

def to_int(x):
    return int(x)

def _run_tests():
    assert to_int('42') == 42, 'am_48'
    assert to_int(3.9) == 3, 'am_48'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_48: all tests passed")
