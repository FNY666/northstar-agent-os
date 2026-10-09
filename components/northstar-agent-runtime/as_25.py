"""transpose utility."""

def transpose(m):
    return [list(r) for r in zip(*m)]


def _selftest():
    assert transpose([[1, 2], [3, 4]]) == [[1, 3], [2, 4]]
    assert transpose([]) == []


if __name__ == "__main__":
    _selftest()
    print("ok")
