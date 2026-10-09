"""ao_17: merge_sorted utility (stdlib only)."""

def merge_sorted(a, b):
    i = j = 0; out = []
    while i < len(a) and j < len(b):
        if a[i] <= b[j]: out.append(a[i]); i += 1
        else: out.append(b[j]); j += 1
    return out + a[i:] + b[j:]


def _self_test():
    assert merge_sorted([1, 3], [2, 4]) == [1, 2, 3, 4], 'merge_sorted([1, 3], [2, 4]) == [1, 2, 3, 4]'
    assert merge_sorted([], [1]) == [1], 'merge_sorted([], [1]) == [1]'


if __name__ == "__main__":
    _self_test()
    print("ok")
