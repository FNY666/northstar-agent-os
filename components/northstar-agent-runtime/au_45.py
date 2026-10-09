"""au_45: Mode of list."""
def mode(xs):
    """Return the most common value (first wins ties)."""
    if not xs:
        raise ValueError('empty')
    return max(dict.fromkeys(xs), key=xs.count)

def _run_tests():
    assert mode([1, 2, 2, 3]) == 2
    assert mode(['x']) == 'x'

if __name__ == "__main__":
    _run_tests()
    print("au_45 OK")
