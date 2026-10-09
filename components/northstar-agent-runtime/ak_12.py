"""ak_12: Median of a list."""

def median(xs):
    s = sorted(xs)
    n = len(s)
    if n % 2: return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2

if __name__ == '__main__':
    assert median([3, 1, 2]) == 2
    assert median([1, 2, 3, 4]) == 2.5
    print('ok')
