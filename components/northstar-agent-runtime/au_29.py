"""au_29: List union."""
def list_union(a, b):
    """Union of two lists, order preserved, deduped."""
    return list(dict.fromkeys(list(a) + list(b)))

def _run_tests():
    assert list_union([1, 2], [2, 3]) == [1, 2, 3]
    assert list_union([], []) == []

if __name__ == "__main__":
    _run_tests()
    print("au_29 OK")
