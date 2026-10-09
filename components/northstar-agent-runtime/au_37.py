"""au_37: Manhattan distance."""
def manhattan_dist(a, b):
    """Manhattan distance between two equal-length points."""
    return sum(abs(x-y) for x, y in zip(a, b))

def _run_tests():
    assert manhattan_dist((0, 0), (3, 4)) == 7
    assert manhattan_dist([1], [4]) == 3

if __name__ == "__main__":
    _run_tests()
    print("au_37 OK")
