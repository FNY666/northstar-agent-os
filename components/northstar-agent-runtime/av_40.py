"""Binary search: index of x in sorted list, or -1."""
def binary_search(sorted_list, x):
    lo, hi = 0, len(sorted_list) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if sorted_list[mid] == x:
            return mid
        if sorted_list[mid] < x:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1
if __name__ == "__main__":
    assert binary_search([1, 3, 5, 7], 5) == 2
    assert binary_search([1, 3, 5], 2) == -1
    assert binary_search([], 1) == -1
    print("ok")
