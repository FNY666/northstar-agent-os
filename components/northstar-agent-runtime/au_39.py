"""au_39: Jaccard similarity."""
def jaccard(a, b):
    """Jaccard similarity of two collections (1.0 if both empty)."""
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)

def _run_tests():
    assert jaccard([1, 2], [2, 3]) == 1/3
    assert jaccard([], []) == 1.0

if __name__ == "__main__":
    _run_tests()
    print("au_39 OK")
