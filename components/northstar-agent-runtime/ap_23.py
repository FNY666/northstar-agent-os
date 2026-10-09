"""rotate utility."""

def rotate(lst, k):
    if not lst: return []
    k %= len(lst)
    return lst[-k:] + lst[:-k] if k else list(lst)


def _self_test():
    assert rotate([1,2,3,4], 1) == [4,1,2,3]
    assert rotate([], 3) == []


if __name__ == "__main__":
    _self_test()
    print("ap_23: OK")
