"""au_19: Find pairs summing to target."""
def pair_sum(xs, target):
    """Return index pairs (i<j) whose values sum to target."""
    return [(i, j) for i in range(len(xs)) for j in range(i+1, len(xs)) if xs[i]+xs[j] == target]

def _run_tests():
    assert pair_sum([1, 2, 3, 4], 5) == [(0, 3), (1, 2)]
    assert pair_sum([1], 2) == []

if __name__ == "__main__":
    _run_tests()
    print("au_19 OK")
