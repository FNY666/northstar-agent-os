"""zip_longest_fill utility."""

def zip_longest_fill(a, b, fill=None):
    n = max(len(a), len(b))
    return [(a[i] if i < len(a) else fill, b[i] if i < len(b) else fill) for i in range(n)]


def _self_test():
    assert zip_longest_fill([1,2],[3]) == [(1,3),(2,None)]
    assert zip_longest_fill([],[]) == []


if __name__ == "__main__":
    _self_test()
    print("ap_21: OK")
