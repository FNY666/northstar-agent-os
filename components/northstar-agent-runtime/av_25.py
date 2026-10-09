"""Jaccard similarity of two collections."""
def jaccard(a, b):
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)
if __name__ == "__main__":
    assert jaccard([1, 2, 3], [2, 3, 4]) == 0.5
    assert jaccard("abc", "abc") == 1.0
    assert jaccard([1], [2]) == 0.0
    print("ok")
