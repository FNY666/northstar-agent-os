"""au_27: Merge two sorted lists."""
def merge_sorted(a, b):
    """Merge two sorted lists into one sorted list."""
    i = j = 0
    out = []
    while i < len(a) and j < len(b):
        if a[i] <= b[j]:
            out.append(a[i]); i += 1
        else:
            out.append(b[j]); j += 1
    return out + a[i:] + b[j:]

def _run_tests():
    assert merge_sorted([1, 3], [2, 4]) == [1, 2, 3, 4]
    assert merge_sorted([], [1]) == [1]

if __name__ == "__main__":
    _run_tests()
    print("au_27 OK")
