"""am_28: ends_with_z utility (stdlib only)."""

def ends_with_z(s):
    return s.endswith('z')

def _run_tests():
    assert ends_with_z('xyz') is True, 'am_28'
    assert ends_with_z('xy') is False, 'am_28'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_28: all tests passed")
