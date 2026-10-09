"""ax_50: rotate utility (stdlib only)."""
def rotate(items, k):
    if not items: return []
    k %= len(items)
    return items[-k:] + items[:-k] if k else list(items)


def run_tests():
    assert (rotate([1,2,3,4], 1)) == [4, 1, 2, 3], 'rotate([1,2,3,4], 1)'
    assert (rotate([], 5)) == [], 'rotate([], 5)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_50: ok")
