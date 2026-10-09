"""ao_40: unique_sorted utility (stdlib only)."""

def unique_sorted(xs):
    return sorted(set(xs))


def _self_test():
    assert unique_sorted([3,1,3,2]) == [1,2,3], 'unique_sorted([3,1,3,2]) == [1,2,3]'
    assert unique_sorted([]) == [], 'unique_sorted([]) == []'


if __name__ == "__main__":
    _self_test()
    print("ok")
