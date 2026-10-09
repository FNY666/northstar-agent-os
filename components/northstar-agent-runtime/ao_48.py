"""ao_48: powerset utility (stdlib only)."""

def powerset(xs):
    import itertools
    return [list(c) for r in range(len(xs)+1) for c in itertools.combinations(xs, r)]


def _self_test():
    assert len(powerset([1,2])) == 4, 'len(powerset([1,2])) == 4'
    assert powerset([]) == [[]], 'powerset([]) == [[]]'


if __name__ == "__main__":
    _self_test()
    print("ok")
