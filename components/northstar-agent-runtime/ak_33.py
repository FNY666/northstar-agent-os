"""ak_33: Sliding window maximum (k)."""

def sliding_max(xs, k):
    return [max(xs[i:i+k]) for i in range(len(xs) - k + 1)]

if __name__ == '__main__':
    assert sliding_max([1, 3, 2, 5], 2) == [3, 3, 5]
    assert sliding_max([4], 1) == [4]
    print('ok')
