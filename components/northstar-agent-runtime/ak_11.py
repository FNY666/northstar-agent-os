"""ak_11: Binary search in sorted list."""

def bsearch(xs, target):
    lo, hi = 0, len(xs)
    while lo < hi:
        mid = (lo + hi) // 2
        if xs[mid] < target: lo = mid + 1
        elif xs[mid] > target: hi = mid
        else: return mid
    return -1

if __name__ == '__main__':
    assert bsearch([1, 3, 5, 7], 5) == 2
    assert bsearch([1, 3, 5], 4) == -1
    print('ok')
