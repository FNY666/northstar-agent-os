"""ax_17: median utility (stdlib only)."""
def median(nums):
    s = sorted(nums)
    n = len(s)
    if not n: raise ValueError('empty')
    m = n // 2
    return (s[m-1] + s[m]) / 2 if n % 2 == 0 else s[m]


def run_tests():
    assert (median([1,3,2])) == 2, 'median([1,3,2])'
    assert (median([1,2,3,4])) == 2.5, 'median([1,2,3,4])'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_17: ok")
