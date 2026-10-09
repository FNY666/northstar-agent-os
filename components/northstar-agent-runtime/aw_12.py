"""Median of a numeric list."""
def median_of(xs):
    s = sorted(xs); n = len(s); m = n // 2
    return s[m] if n % 2 else (s[m-1] + s[m]) / 2
if __name__ == "__main__":
    assert median_of([3,1,2]) == 2
    assert median_of([1,2,3,4]) == 2.5
    assert median_of([7]) == 7
    print("ok")
