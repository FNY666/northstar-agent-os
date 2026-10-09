"""au_36: Euclidean distance."""
import math
def euclidean_dist(a, b):
    """Euclidean distance between two equal-length points."""
    return math.sqrt(sum((x-y)**2 for x, y in zip(a, b)))

def _run_tests():
    assert euclidean_dist((0, 0), (3, 4)) == 5.0
    assert euclidean_dist([1], [1]) == 0.0

if __name__ == "__main__":
    _run_tests()
    print("au_36 OK")
