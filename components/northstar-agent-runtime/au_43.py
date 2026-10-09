"""au_43: Top-k largest."""
import heapq
def top_k(xs, k):
    """Return the k largest elements, descending."""
    return heapq.nlargest(k, xs)

def _run_tests():
    assert top_k([1, 5, 3], 2) == [5, 3]
    assert top_k([], 3) == []

if __name__ == "__main__":
    _run_tests()
    print("au_43 OK")
