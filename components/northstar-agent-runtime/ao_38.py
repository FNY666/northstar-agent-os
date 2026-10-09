"""ao_38: transpose utility (stdlib only)."""

def transpose(m):
    return [list(r) for r in zip(*m)]


def _self_test():
    assert transpose([[1,2],[3,4]]) == [[1,3],[2,4]], 'transpose([[1,2],[3,4]]) == [[1,3],[2,4]]'
    assert transpose([]) == [], 'transpose([]) == []'


if __name__ == "__main__":
    _self_test()
    print("ok")
