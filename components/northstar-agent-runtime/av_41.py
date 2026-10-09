"""Merge two sorted lists into one sorted list."""
def merge_sorted(a, b):
    i = j = 0
    out = []
    while i < len(a) and j < len(b):
        if a[i] <= b[j]:
            out.append(a[i]); i += 1
        else:
            out.append(b[j]); j += 1
    out.extend(a[i:]); out.extend(b[j:])
    return out
if __name__ == "__main__":
    assert merge_sorted([1, 3], [2, 4]) == [1, 2, 3, 4]
    assert merge_sorted([], [1]) == [1]
    assert merge_sorted([5], []) == [5]
    print("ok")
