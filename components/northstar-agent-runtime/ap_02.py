"""chunk utility."""

def chunk(lst, n):
    return [lst[i:i+n] for i in range(0, len(lst), n)]


def _self_test():
    assert chunk([1,2,3,4,5], 2) == [[1,2],[3,4],[5]]
    assert chunk([], 3) == []


if __name__ == "__main__":
    _self_test()
    print("ap_02: OK")
