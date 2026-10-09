"""interleave utility."""

def interleave(a, b):
    out = []
    for x, y in zip(a, b):
        out += [x, y]
    return out + list(a[len(b):]) + list(b[len(a):])


def _self_test():
    assert interleave([1,3],[2,4]) == [1,2,3,4]
    assert interleave([1],[2,3]) == [1,2,3]


if __name__ == "__main__":
    _self_test()
    print("ap_24: OK")
