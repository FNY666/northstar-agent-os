"""Top k largest items. stdlib only."""

def top_k(xs, k):
    return sorted(xs, reverse=True)[:k]

def test():
    assert top_k([3,1,2], 2) == [3,2]
    assert top_k([], 3) == []
    assert top_k([5], 9) == [5]

if __name__ == '__main__':
    test(); print('ok')
