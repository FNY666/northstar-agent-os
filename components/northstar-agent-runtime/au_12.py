"""au_12: Most frequent element."""
def most_common(xs):
    """Return the most frequent element (first wins ties)."""
    best, bn = None, 0
    for x in dict.fromkeys(xs):
        c = xs.count(x)
        if c > bn:
            best, bn = x, c
    return best

def _run_tests():
    assert most_common([1, 2, 2, 3]) == 2
    assert most_common(['a']) == 'a'

if __name__ == "__main__":
    _run_tests()
    print("au_12 OK")
