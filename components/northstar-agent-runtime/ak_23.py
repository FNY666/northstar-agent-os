"""ak_23: Pairwise sum of two lists."""

def pairwise_sum(a, b):
    return [x + y for x, y in zip(a, b)]

if __name__ == '__main__':
    assert pairwise_sum([1, 2], [3, 4]) == [4, 6]
    assert pairwise_sum([], []) == []
    print('ok')
