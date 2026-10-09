"""au_30: List difference."""
def list_diff(a, b):
    """Items of a not in b, order preserved."""
    sb = set(b)
    return [x for x in a if x not in sb]

def _run_tests():
    assert list_diff([1, 2, 3], [2]) == [1, 3]
    assert list_diff([1], [1]) == []

if __name__ == "__main__":
    _run_tests()
    print("au_30 OK")
