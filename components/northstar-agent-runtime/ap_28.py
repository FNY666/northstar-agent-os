"""is_sorted utility."""

def is_sorted(lst):
    return all(a <= b for a, b in zip(lst, lst[1:]))


def _self_test():
    assert is_sorted([1,2,3])
    assert not is_sorted([3,1])


if __name__ == "__main__":
    _self_test()
    print("ap_28: OK")
