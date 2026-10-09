"""au_18: Running total."""
def running_sum(xs):
    """Return cumulative sums."""
    out, t = [], 0
    for x in xs:
        t += x; out.append(t)
    return out

def _run_tests():
    assert running_sum([1, 2, 3]) == [1, 3, 6]
    assert running_sum([]) == []

if __name__ == "__main__":
    _run_tests()
    print("au_18 OK")
