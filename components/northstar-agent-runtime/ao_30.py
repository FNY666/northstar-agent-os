"""ao_30: hamming utility (stdlib only)."""

def hamming(a, b):
    return sum(c1 != c2 for c1, c2 in zip(a, b))


def _self_test():
    assert hamming('abc', 'abd') == 1, "hamming('abc', 'abd') == 1"
    assert hamming('abc', 'abc') == 0, "hamming('abc', 'abc') == 0"


if __name__ == "__main__":
    _self_test()
    print("ok")
