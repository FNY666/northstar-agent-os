"""Median of numbers."""
def median(nums):
    s = sorted(nums)
    n = len(s)
    if n == 0:
        raise ValueError("empty")
    m = n // 2
    return s[m] if n % 2 else (s[m - 1] + s[m]) / 2
if __name__ == "__main__":
    assert median([3, 1, 2]) == 2
    assert median([1, 2, 3, 4]) == 2.5
    assert median([9]) == 9
    print("ok")
