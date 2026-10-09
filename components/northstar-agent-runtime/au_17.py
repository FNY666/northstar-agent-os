"""au_17: Split list into chunks."""
def chunk(xs, n):
    """Split xs into chunks of size n."""
    return [xs[i:i+n] for i in range(0, len(xs), n)]

def _run_tests():
    assert chunk([1, 2, 3, 4], 2) == [[1, 2], [3, 4]]
    assert chunk([1], 5) == [[1]]

if __name__ == "__main__":
    _run_tests()
    print("au_17 OK")
