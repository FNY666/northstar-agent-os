"""ao_46: partition utility (stdlib only)."""

def partition(xs, pred):
    t, f = [], []
    for x in xs: (t if pred(x) else f).append(x)
    return t, f


def _self_test():
    assert partition([1,2,3], lambda x: x % 2) == ([1,3],[2]), 'partition([1,2,3], lambda x: x % 2) == ([1,3],[2])'
    assert partition([], bool) == ([],[]), 'partition([], bool) == ([],[])'


if __name__ == "__main__":
    _self_test()
    print("ok")
