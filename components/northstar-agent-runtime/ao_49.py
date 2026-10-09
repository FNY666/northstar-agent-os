"""ao_49: perm_count utility (stdlib only)."""

def perm_count(xs, r=None):
    import math
    return math.perm(len(xs), r or len(xs))


def _self_test():
    assert perm_count([1,2,3]) == 6, 'perm_count([1,2,3]) == 6'
    assert perm_count([1,2,3], 2) == 6, 'perm_count([1,2,3], 2) == 6'


if __name__ == "__main__":
    _self_test()
    print("ok")
