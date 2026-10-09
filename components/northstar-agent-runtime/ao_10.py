"""ao_10: chunk utility (stdlib only)."""

def chunk(xs, n):
    return [xs[i:i + n] for i in range(0, len(xs), n)]


def _self_test():
    assert chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]], 'chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]'
    assert chunk([], 3) == [], 'chunk([], 3) == []'


if __name__ == "__main__":
    _self_test()
    print("ok")
