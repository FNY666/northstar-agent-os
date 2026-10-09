"""Utility ay_37: truthy_count."""


def truthy_count(lst):
    """Return truthy_count result."""
    return sum(1 for x in lst if x)


def _run_tests():
    assert truthy_count([0,1,'', 'a', None]) == 2
    assert truthy_count([]) == 0


if __name__ == '__main__':
    _run_tests()
    print('OK')
