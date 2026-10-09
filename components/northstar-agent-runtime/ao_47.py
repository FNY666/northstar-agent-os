"""ao_47: cartesian utility (stdlib only)."""

def cartesian(a, b):
    import itertools
    return list(itertools.product(a, b))


def _self_test():
    assert cartesian([1,2],['a']) == [(1,'a'),(2,'a')], "cartesian([1,2],['a']) == [(1,'a'),(2,'a')]"
    assert cartesian([], [1]) == [], 'cartesian([], [1]) == []'


if __name__ == "__main__":
    _self_test()
    print("ok")
