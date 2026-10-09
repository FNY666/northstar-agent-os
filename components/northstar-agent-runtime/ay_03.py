"""Utility ay_03: dedup_keep_order."""


def dedup_keep_order(lst):
    """Return dedup_keep_order result."""
    seen=set(); return [x for x in lst if not (x in seen or seen.add(x))]


def _run_tests():
    assert dedup_keep_order([1,2,2,3,1]) == [1,2,3]
    assert dedup_keep_order([]) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
