"""ao_13: median utility (stdlib only)."""

def median(xs):
    s = sorted(xs); n = len(s); m = n // 2
    return s[m] if n % 2 else (s[m - 1] + s[m]) / 2


def _self_test():
    assert median([1, 3, 2]) == 2, 'median([1, 3, 2]) == 2'
    assert median([1, 2, 3, 4]) == 2.5, 'median([1, 2, 3, 4]) == 2.5'


if __name__ == "__main__":
    _self_test()
    print("ok")
