"""ao_41: pair_sum utility (stdlib only)."""

def pair_sum(xs, target):
    seen = set()
    for x in xs:
        if target - x in seen: return (target - x, x)
        seen.add(x)
    return None


def _self_test():
    assert pair_sum([1,2,3,4], 7) == (3, 4), 'pair_sum([1,2,3,4], 7) == (3, 4)'
    assert pair_sum([1,2], 9) is None, 'pair_sum([1,2], 9) is None'


if __name__ == "__main__":
    _self_test()
    print("ok")
