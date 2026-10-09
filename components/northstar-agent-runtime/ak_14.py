"""ak_14: Chunk a list into size-n pieces."""

def chunks(xs, n):
    return [xs[i:i+n] for i in range(0, len(xs), n)]

if __name__ == '__main__':
    assert chunks([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]
    assert chunks([], 3) == []
    print('ok')
