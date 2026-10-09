"""most_common utility."""

def most_common(xs):
    return max(set(xs), key=xs.count) if xs else None


def _selftest():
    assert most_common([1, 2, 2, 3]) == 2
    assert most_common([]) is None


if __name__ == "__main__":
    _selftest()
    print("ok")
