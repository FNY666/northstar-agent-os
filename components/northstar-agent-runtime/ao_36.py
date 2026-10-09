"""ao_36: running_total utility (stdlib only)."""

def running_total(xs):
    import itertools
    return list(itertools.accumulate(xs))


def _self_test():
    assert running_total([1,2,3]) == [1,3,6], 'running_total([1,2,3]) == [1,3,6]'
    assert running_total([]) == [], 'running_total([]) == []'


if __name__ == "__main__":
    _self_test()
    print("ok")
