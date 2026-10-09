"""ao_37: sliding_window utility (stdlib only)."""

def sliding_window(xs, n):
    return [xs[i:i+n] for i in range(len(xs) - n + 1)]


def _self_test():
    assert sliding_window([1,2,3,4], 2) == [[1,2],[2,3],[3,4]], 'sliding_window([1,2,3,4], 2) == [[1,2],[2,3],[3,4]]'
    assert sliding_window([1], 2) == [], 'sliding_window([1], 2) == []'


if __name__ == "__main__":
    _self_test()
    print("ok")
