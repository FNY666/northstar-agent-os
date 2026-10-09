"""ao_35: top_n utility (stdlib only)."""

def top_n(xs, n):
    import heapq
    return heapq.nlargest(n, xs)


def _self_test():
    assert top_n([3,1,2,5,4], 2) == [5,4], 'top_n([3,1,2,5,4], 2) == [5,4]'
    assert top_n([], 3) == [], 'top_n([], 3) == []'


if __name__ == "__main__":
    _self_test()
    print("ok")
