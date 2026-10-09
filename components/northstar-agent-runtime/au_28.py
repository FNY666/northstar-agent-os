"""au_28: List intersection."""
def intersection(a, b):
    """Items of a also in b, order of a, deduped."""
    sb = set(b)
    return [x for x in dict.fromkeys(a) if x in sb]

def _run_tests():
    assert intersection([1, 2, 3], [2, 4]) == [2]
    assert intersection([1], [2]) == []

if __name__ == "__main__":
    _run_tests()
    print("au_28 OK")
