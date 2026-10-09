"""au_33: Second largest value."""
def second_largest(xs):
    """Return the second-largest distinct value."""
    u = sorted(set(xs))
    if len(u) < 2:
        raise ValueError('need 2 distinct')
    return u[-2]

def _run_tests():
    assert second_largest([1, 3, 2]) == 2
    assert second_largest([5, 5, 1]) == 1

if __name__ == "__main__":
    _run_tests()
    print("au_33 OK")
