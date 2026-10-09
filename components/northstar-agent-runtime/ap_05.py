"""sliding utility."""

def sliding(lst, n):
    return [lst[i:i+n] for i in range(len(lst)-n+1)]


def _self_test():
    assert sliding([1,2,3,4], 2) == [[1,2],[2,3],[3,4]]
    assert sliding([1], 2) == []


if __name__ == "__main__":
    _self_test()
    print("ap_05: OK")
