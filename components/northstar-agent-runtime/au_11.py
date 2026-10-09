"""au_11: Dedupe preserving order."""
def unique(xs):
    """Return unique items preserving first-seen order."""
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x); out.append(x)
    return out

def _run_tests():
    assert unique([1, 2, 1, 3]) == [1, 2, 3]
    assert unique([]) == []

if __name__ == "__main__":
    _run_tests()
    print("au_11 OK")
